use crate::connection_metrics::{ConnectionMetricsResponse, ConnectionMetricsTracker};
use crate::diagnostics::{AppDiagnostics, RuntimeActionSource};
use crate::runtime_control::RuntimeControls;
use crate::updates::{NativeUpdater, UpdateStatusResponse};
use crate::{
    preferences::{AppPreferenceStore, DnsProvider},
    NativeApplication, PushRegistrationScheduler, SplitTunnelScheduler,
};
use nelomai_client_api::DiagnosticUploadResponse;
use nelomai_client_application::{ApplicationError, LoginParameters};
use nelomai_client_container::RuntimeSwitchStatusV1;
use nelomai_client_core::{
    split_tunnel_active, ConnectOptions, CoreApiError, CoreError, CoreState, Phase,
    SplitTunnelContext,
};
use nelomai_client_tunnel::{TunnelCapabilities, TunnelPlatform};
use nelomai_contracts::{
    AppNotificationList, AppNotificationReadResponse, BindPeerRequest, Bootstrap, Connection,
    ConnectionIntentCapability, EgressMode, Layer, PeerBinding, PeerBindingResponse, PeerOptions,
    Platform, ProbeResults, RouteMode, RuntimeSlot, SplitTunnelAddressRuleScope,
    SplitTunnelAddressRuleUpdate, SplitTunnelMode, SplitTunnelSelectedPackage,
    SplitTunnelSettingsUpdate, TicConnectionMode,
};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_tunnel_android::TunnelAndroidExt;

#[cfg(any(target_os = "android", test))]
static ANDROID_BACKGROUND_PROVISION_GATE: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

#[cfg(target_os = "android")]
static ANDROID_QUICK_RECONCILE_RETRY_AFTER_UNIX: AtomicI64 = AtomicI64::new(0);
#[cfg(target_os = "android")]
static ANDROID_UI_START_STOP_COORDINATOR: AndroidUiStartStopCoordinator =
    AndroidUiStartStopCoordinator::new();
#[cfg(any(target_os = "android", test))]
static ANDROID_DESIRED_ACTIVE_PROJECTION: AndroidDesiredActiveProjection =
    AndroidDesiredActiveProjection::new();

#[cfg(any(target_os = "android", test))]
struct AndroidDesiredActiveProjection {
    value: std::sync::atomic::AtomicU8,
}

#[cfg(any(target_os = "android", test))]
impl AndroidDesiredActiveProjection {
    const UNKNOWN: u8 = 0;
    const STOPPED: u8 = 1;
    const ACTIVE: u8 = 2;

    const fn new() -> Self {
        Self {
            value: std::sync::atomic::AtomicU8::new(Self::UNKNOWN),
        }
    }

    fn observe_confirmed(&self, desired_active: bool) {
        self.value.store(
            if desired_active {
                Self::ACTIVE
            } else {
                Self::STOPPED
            },
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    fn observe_snapshot(&self, changed: bool, desired_active: Option<bool>) {
        if !changed {
            return;
        }
        if let Some(desired_active) = desired_active {
            self.observe_confirmed(desired_active);
        } else {
            self.value
                .store(Self::UNKNOWN, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn status_unavailable_fallback(&self) -> nelomai_client_core::ConnectionIntentStatus {
        if self.value.load(std::sync::atomic::Ordering::SeqCst) == Self::STOPPED {
            nelomai_client_core::ConnectionIntentStatus::None
        } else {
            nelomai_client_core::ConnectionIntentStatus::Recovering
        }
    }
}

#[cfg(any(target_os = "android", test))]
fn android_status_unavailable_fallback() -> nelomai_client_core::ConnectionIntentStatus {
    ANDROID_DESIRED_ACTIVE_PROJECTION.status_unavailable_fallback()
}

#[cfg(not(any(target_os = "android", test)))]
fn android_status_unavailable_fallback() -> nelomai_client_core::ConnectionIntentStatus {
    nelomai_client_core::ConnectionIntentStatus::Recovering
}

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Copy)]
struct AndroidUiStartTicket(u64);

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Copy)]
struct AndroidProjectionTicket(u64);

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Copy)]
struct AndroidProjectionObservationTicket {
    projection_epoch: u64,
    observation_sequence: u64,
}

#[cfg(any(target_os = "android", test))]
struct AndroidUiStartStopCoordinator {
    epoch: std::sync::atomic::AtomicU64,
    projection_epoch: std::sync::atomic::AtomicU64,
    observation_sequence: std::sync::atomic::AtomicU64,
    applied_observation_sequence: std::sync::atomic::AtomicU64,
    pending_projection: std::sync::atomic::AtomicU8,
    start_gate: tokio::sync::Mutex<()>,
    side_effect_gate: std::sync::Mutex<()>,
}

#[cfg(any(target_os = "android", test))]
impl AndroidUiStartStopCoordinator {
    const fn new() -> Self {
        Self {
            epoch: std::sync::atomic::AtomicU64::new(0),
            projection_epoch: std::sync::atomic::AtomicU64::new(0),
            observation_sequence: std::sync::atomic::AtomicU64::new(0),
            applied_observation_sequence: std::sync::atomic::AtomicU64::new(0),
            pending_projection: std::sync::atomic::AtomicU8::new(Self::PROJECTION_STABLE),
            start_gate: tokio::sync::Mutex::const_new(()),
            side_effect_gate: std::sync::Mutex::new(()),
        }
    }

    const PROJECTION_STABLE: u8 = 0;
    const PROJECTION_STOPPING: u8 = 1;
    const PROJECTION_STARTING: u8 = 2;
    const PROJECTION_TOGGLING: u8 = 3;

    fn start_ticket(&self) -> AndroidUiStartTicket {
        AndroidUiStartTicket(self.epoch.load(std::sync::atomic::Ordering::SeqCst))
    }

    fn projection_ticket(&self) -> AndroidProjectionObservationTicket {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        AndroidProjectionObservationTicket {
            projection_epoch: self
                .projection_epoch
                .load(std::sync::atomic::Ordering::SeqCst),
            observation_sequence: self
                .observation_sequence
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .wrapping_add(1),
        }
    }

    fn next_projection_ticket(&self) -> AndroidProjectionTicket {
        AndroidProjectionTicket(
            self.projection_epoch
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .wrapping_add(1),
        )
    }

    fn begin_projected_start_locked(
        &self,
        ticket: AndroidUiStartTicket,
        projection: &AndroidDesiredActiveProjection,
    ) -> Result<AndroidProjectionTicket, CommandError> {
        self.ensure_current(ticket)?;
        let projection_ticket = self.next_projection_ticket();
        self.pending_projection.store(
            Self::PROJECTION_STARTING,
            std::sync::atomic::Ordering::SeqCst,
        );
        projection.observe_snapshot(true, None);
        Ok(projection_ticket)
    }

    #[cfg(test)]
    fn begin_projected_start(
        &self,
        ticket: AndroidUiStartTicket,
        projection: &AndroidDesiredActiveProjection,
    ) -> Result<AndroidProjectionTicket, CommandError> {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.begin_projected_start_locked(ticket, projection)
    }

    fn commit_projected_start(
        &self,
        ticket: AndroidUiStartTicket,
        projection_ticket: AndroidProjectionTicket,
        projection: &AndroidDesiredActiveProjection,
        desired_active: bool,
    ) -> Result<(), CommandError> {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_current(ticket)?;
        if !self.projection_is_current(projection_ticket) {
            return Err(CommandError::new(
                "connection_intent_cancelled",
                "Подключение отменено",
            ));
        }
        projection.observe_confirmed(desired_active);
        self.pending_projection
            .store(Self::PROJECTION_STABLE, std::sync::atomic::Ordering::SeqCst);
        self.next_projection_ticket();
        Ok(())
    }

    fn begin_projected_stop_locked(&self) -> AndroidProjectionTicket {
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let projection_ticket = self.next_projection_ticket();
        self.pending_projection.store(
            Self::PROJECTION_STOPPING,
            std::sync::atomic::Ordering::SeqCst,
        );
        projection_ticket
    }

    #[cfg(test)]
    fn begin_projected_stop(&self) -> AndroidProjectionTicket {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.begin_projected_stop_locked()
    }

    fn begin_projected_clear_locked(&self) -> AndroidProjectionTicket {
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let projection_ticket = self.next_projection_ticket();
        self.pending_projection.store(
            Self::PROJECTION_STOPPING,
            std::sync::atomic::Ordering::SeqCst,
        );
        projection_ticket
    }

    #[cfg(test)]
    fn begin_projected_clear(&self) -> AndroidProjectionTicket {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.begin_projected_clear_locked()
    }

    fn begin_projected_toggle_locked(
        &self,
        projection: &AndroidDesiredActiveProjection,
    ) -> AndroidProjectionTicket {
        let projection_ticket = self.next_projection_ticket();
        self.pending_projection.store(
            Self::PROJECTION_TOGGLING,
            std::sync::atomic::Ordering::SeqCst,
        );
        projection.observe_snapshot(true, None);
        projection_ticket
    }

    #[cfg(test)]
    fn begin_projected_toggle(
        &self,
        projection: &AndroidDesiredActiveProjection,
    ) -> AndroidProjectionTicket {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.begin_projected_toggle_locked(projection)
    }

    fn dispatch_projected_stop<F, T>(&self, dispatch: F) -> (AndroidProjectionTicket, T)
    where
        F: FnOnce() -> T,
    {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let projection_ticket = self.begin_projected_stop_locked();
        (projection_ticket, dispatch())
    }

    fn dispatch_projected_clear<F, T>(&self, dispatch: F) -> (AndroidProjectionTicket, T)
    where
        F: FnOnce() -> T,
    {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let projection_ticket = self.begin_projected_clear_locked();
        (projection_ticket, dispatch())
    }

    fn dispatch_projected_toggle<F, T>(
        &self,
        projection: &AndroidDesiredActiveProjection,
        dispatch: F,
    ) -> (AndroidProjectionTicket, T)
    where
        F: FnOnce() -> T,
    {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let projection_ticket = self.begin_projected_toggle_locked(projection);
        (projection_ticket, dispatch())
    }

    fn commit_projected_action(
        &self,
        ticket: AndroidProjectionTicket,
        projection: &AndroidDesiredActiveProjection,
        desired_active: bool,
    ) -> bool {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.projection_is_current(ticket) {
            return false;
        }
        projection.observe_confirmed(desired_active);
        self.pending_projection
            .store(Self::PROJECTION_STABLE, std::sync::atomic::Ordering::SeqCst);
        self.next_projection_ticket();
        true
    }

    fn finish_projected_action(&self, ticket: AndroidProjectionTicket) {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.finish_projected_action_locked(ticket);
    }

    fn finish_projected_action_locked(&self, ticket: AndroidProjectionTicket) {
        if self.projection_is_current(ticket) {
            self.pending_projection
                .store(Self::PROJECTION_STABLE, std::sync::atomic::Ordering::SeqCst);
            self.next_projection_ticket();
        }
    }

    fn observe_projected_status(
        &self,
        ticket: AndroidProjectionObservationTicket,
        projection: &AndroidDesiredActiveProjection,
        desired_active: bool,
    ) -> bool {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.projection_observation_is_current(ticket) {
            return false;
        }
        let pending = self
            .pending_projection
            .load(std::sync::atomic::Ordering::SeqCst);
        if !Self::projection_observation_matches_pending(pending, Some(desired_active)) {
            return false;
        }
        projection.observe_confirmed(desired_active);
        self.applied_observation_sequence.store(
            ticket.observation_sequence,
            std::sync::atomic::Ordering::SeqCst,
        );
        true
    }

    fn observe_projected_snapshot(
        &self,
        ticket: AndroidProjectionObservationTicket,
        projection: &AndroidDesiredActiveProjection,
        changed: bool,
        desired_active: Option<bool>,
    ) -> bool {
        if !changed {
            return true;
        }
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.projection_observation_is_current(ticket) {
            return false;
        }
        let pending = self
            .pending_projection
            .load(std::sync::atomic::Ordering::SeqCst);
        if !Self::projection_observation_matches_pending(pending, desired_active) {
            return false;
        }
        self.applied_observation_sequence.store(
            ticket.observation_sequence,
            std::sync::atomic::Ordering::SeqCst,
        );
        projection.observe_snapshot(true, desired_active);
        true
    }

    fn finalize_projected_status(
        &self,
        ticket: AndroidProjectionObservationTicket,
        projection: &AndroidDesiredActiveProjection,
        desired_active: Option<bool>,
    ) -> (bool, nelomai_client_core::ConnectionIntentStatus) {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let observation_is_current = self.projection_observation_is_current(ticket);
        let pending = self
            .pending_projection
            .load(std::sync::atomic::Ordering::SeqCst);
        let status_is_current = observation_is_current
            && desired_active.is_some()
            && Self::projection_observation_matches_pending(pending, desired_active);
        if status_is_current {
            if let Some(desired_active) = desired_active {
                projection.observe_confirmed(desired_active);
            }
        }
        if observation_is_current && (desired_active.is_none() || status_is_current) {
            self.applied_observation_sequence.store(
                ticket.observation_sequence,
                std::sync::atomic::Ordering::SeqCst,
            );
        }
        (status_is_current, projection.status_unavailable_fallback())
    }

    #[cfg(test)]
    fn projected_status_fallback(
        &self,
        ticket: AndroidProjectionObservationTicket,
        projection: &AndroidDesiredActiveProjection,
    ) -> nelomai_client_core::ConnectionIntentStatus {
        let _side_effect_gate = self
            .side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.projection_observation_is_current(ticket) {
            self.applied_observation_sequence.store(
                ticket.observation_sequence,
                std::sync::atomic::Ordering::SeqCst,
            );
        }
        projection.status_unavailable_fallback()
    }

    fn projection_is_current(&self, ticket: AndroidProjectionTicket) -> bool {
        ticket.0
            == self
                .projection_epoch
                .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn projection_observation_is_current(
        &self,
        ticket: AndroidProjectionObservationTicket,
    ) -> bool {
        ticket.projection_epoch
            == self
                .projection_epoch
                .load(std::sync::atomic::Ordering::SeqCst)
            && ticket.observation_sequence
                >= self
                    .applied_observation_sequence
                    .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn projection_observation_matches_pending(pending: u8, desired_active: Option<bool>) -> bool {
        match pending {
            Self::PROJECTION_STABLE => true,
            Self::PROJECTION_STOPPING => desired_active == Some(false),
            Self::PROJECTION_STARTING => desired_active == Some(true),
            Self::PROJECTION_TOGGLING => false,
            _ => false,
        }
    }

    async fn run_start<F, Fut, T>(
        &self,
        ticket: AndroidUiStartTicket,
        start: F,
    ) -> Result<T, CommandError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, CommandError>>,
    {
        let _gate = self.start_gate.lock().await;
        self.ensure_current(ticket)?;
        let result = start().await;
        self.ensure_current(ticket)?;
        result
    }

    #[cfg(test)]
    async fn run_stop<F, Fut, T>(&self, stop: F) -> Result<T, CommandError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, CommandError>>,
    {
        {
            let _side_effect_gate = self
                .side_effect_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        stop().await
    }

    fn run_start_side_effect<Fut, T>(
        &self,
        ticket: AndroidUiStartTicket,
        future: Fut,
    ) -> AndroidUiStartSideEffect<'_, Fut>
    where
        Fut: std::future::Future<Output = Result<T, CommandError>>,
    {
        AndroidUiStartSideEffect {
            coordinator: self,
            ticket,
            future: Box::pin(future),
            first_poll: true,
        }
    }

    fn run_projected_start_side_effect<'a, Fut, T>(
        &'a self,
        ticket: AndroidUiStartTicket,
        projection: &'a AndroidDesiredActiveProjection,
        future: Fut,
    ) -> AndroidProjectedStartSideEffect<'a, Fut>
    where
        Fut: std::future::Future<Output = Result<T, CommandError>>,
    {
        AndroidProjectedStartSideEffect {
            coordinator: self,
            ticket,
            projection,
            projection_ticket: None,
            future: Box::pin(future),
        }
    }

    fn ensure_current(&self, ticket: AndroidUiStartTicket) -> Result<(), CommandError> {
        if android_start_epoch_is_current(
            ticket.0,
            self.epoch.load(std::sync::atomic::Ordering::SeqCst),
        ) {
            Ok(())
        } else {
            Err(CommandError::new(
                "connection_intent_cancelled",
                "Подключение отменено",
            ))
        }
    }
}

#[cfg(any(target_os = "android", test))]
struct AndroidProjectedStartSideEffect<'a, Fut> {
    coordinator: &'a AndroidUiStartStopCoordinator,
    ticket: AndroidUiStartTicket,
    projection: &'a AndroidDesiredActiveProjection,
    projection_ticket: Option<AndroidProjectionTicket>,
    future: std::pin::Pin<Box<Fut>>,
}

#[cfg(any(target_os = "android", test))]
impl<Fut, T> std::future::Future for AndroidProjectedStartSideEffect<'_, Fut>
where
    Fut: std::future::Future<Output = Result<T, CommandError>>,
{
    type Output = Result<(AndroidProjectionTicket, T), CommandError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        if this.projection_ticket.is_none() {
            let _side_effect_gate = this
                .coordinator
                .side_effect_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let projection_ticket = match this
                .coordinator
                .begin_projected_start_locked(this.ticket, this.projection)
            {
                Ok(projection_ticket) => projection_ticket,
                Err(error) => return std::task::Poll::Ready(Err(error)),
            };
            this.projection_ticket = Some(projection_ticket);
            return match this.future.as_mut().poll(context) {
                std::task::Poll::Ready(Ok(value)) => {
                    std::task::Poll::Ready(Ok((projection_ticket, value)))
                }
                std::task::Poll::Ready(Err(error)) => {
                    this.coordinator
                        .finish_projected_action_locked(projection_ticket);
                    std::task::Poll::Ready(Err(error))
                }
                std::task::Poll::Pending => std::task::Poll::Pending,
            };
        }

        match this.future.as_mut().poll(context) {
            std::task::Poll::Ready(Ok(value)) => {
                let projection_ticket = this
                    .projection_ticket
                    .expect("projected Start must initialize its ticket before a later poll");
                std::task::Poll::Ready(Ok((projection_ticket, value)))
            }
            std::task::Poll::Ready(Err(error)) => {
                if let Some(projection_ticket) = this.projection_ticket {
                    this.coordinator.finish_projected_action(projection_ticket);
                }
                std::task::Poll::Ready(Err(error))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[cfg(any(target_os = "android", test))]
struct AndroidUiStartSideEffect<'a, Fut> {
    coordinator: &'a AndroidUiStartStopCoordinator,
    ticket: AndroidUiStartTicket,
    future: std::pin::Pin<Box<Fut>>,
    first_poll: bool,
}

#[cfg(any(target_os = "android", test))]
impl<Fut, T> std::future::Future for AndroidUiStartSideEffect<'_, Fut>
where
    Fut: std::future::Future<Output = Result<T, CommandError>>,
{
    type Output = Result<T, CommandError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        if this.first_poll {
            let _side_effect_gate = this
                .coordinator
                .side_effect_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Err(error) = this.coordinator.ensure_current(this.ticket) {
                return std::task::Poll::Ready(Err(error));
            }
            this.first_poll = false;
            return this.future.as_mut().poll(context);
        }
        this.future.as_mut().poll(context)
    }
}

#[cfg(target_os = "android")]
struct AndroidLegacyStartAttempt {
    application: Arc<NativeApplication>,
    epoch: nelomai_client_core::StartCancellationEpoch,
}

#[cfg(target_os = "android")]
impl AndroidLegacyStartAttempt {
    fn new(application: Arc<NativeApplication>) -> Self {
        let epoch = application.begin_start_attempt();
        Self { application, epoch }
    }
}

#[cfg(target_os = "android")]
impl Drop for AndroidLegacyStartAttempt {
    fn drop(&mut self) {
        self.application.finish_start_attempt();
    }
}

#[cfg(any(target_os = "android", test))]
const ANDROID_BACKGROUND_REFRESH_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;

#[cfg(any(target_os = "android", test))]
const ANDROID_DISABLED_CAPABILITY_EXPIRES_AT: &str = "1970-01-01T00:00:01Z";

#[cfg(target_os = "android")]
const ANDROID_QUICK_RECONCILE_RETRY_SECONDS: i64 = 15;

const STARTUP_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(45);

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AndroidBackgroundProvisionMode {
    Noop,
    UiAuthenticatedTwoPhase,
    RefreshStoredCapability,
    Legacy,
}

#[cfg(any(target_os = "android", test))]
struct AndroidBackgroundCapabilitySnapshot {
    revision: i64,
    enabled: bool,
    expires_at: String,
    expires_at_unix: i64,
}

#[cfg(any(target_os = "android", test))]
fn android_background_capability_snapshot(
    capability: Option<&ConnectionIntentCapability>,
    now: i64,
) -> AndroidBackgroundCapabilitySnapshot {
    let enabled = capability.is_some_and(|value| value.is_recovery_enabled_at(now));
    let expires_at_unix = if enabled {
        capability
            .and_then(ConnectionIntentCapability::expires_at_unix)
            .unwrap_or(1)
    } else {
        1
    };
    AndroidBackgroundCapabilitySnapshot {
        revision: capability
            .filter(|value| value.revision > 0)
            .map(|value| value.revision)
            .unwrap_or(0),
        enabled,
        expires_at: if enabled {
            capability
                .map(|value| value.expires_at.clone())
                .unwrap_or_else(|| ANDROID_DISABLED_CAPABILITY_EXPIRES_AT.to_string())
        } else {
            ANDROID_DISABLED_CAPABILITY_EXPIRES_AT.to_string()
        },
        expires_at_unix,
    }
}

#[cfg(any(target_os = "android", test))]
fn android_background_capability_matches(
    status: &tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse,
    desired: &AndroidBackgroundCapabilitySnapshot,
) -> bool {
    status.capability_revision == desired.revision
        && status.capability_enabled == desired.enabled
        && (!desired.enabled || status.capability_expires_at_unix == Some(desired.expires_at_unix))
}

#[cfg(any(target_os = "android", test))]
fn android_background_provision_mode(
    status: &tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse,
    device_id: &str,
    desired_capability: &AndroidBackgroundCapabilitySnapshot,
    now: i64,
) -> AndroidBackgroundProvisionMode {
    let same_device = status.device_id.as_deref() == Some(device_id);
    let token_is_fresh = status.expires_at_unix.is_some_and(|expires_at| {
        expires_at > now.saturating_add(ANDROID_BACKGROUND_REFRESH_WINDOW_SECONDS)
    });
    let stored_capability_available = status.capability_enabled
        && status
            .capability_expires_at_unix
            .is_some_and(|expires_at| expires_at > now);
    if status.mutation_pending {
        AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase
    } else if status.configured
        && status.mutation_ready
        && same_device
        && android_background_capability_matches(status, desired_capability)
        && (!status.capability_enabled
            || status
                .capability_expires_at_unix
                .is_some_and(|expires_at| expires_at > now))
        && token_is_fresh
    {
        AndroidBackgroundProvisionMode::Noop
    } else if status.configured && status.mutation_ready && same_device && token_is_fresh {
        AndroidBackgroundProvisionMode::RefreshStoredCapability
    } else if desired_capability.enabled || stored_capability_available {
        AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase
    } else {
        AndroidBackgroundProvisionMode::Legacy
    }
}

async fn bootstrap_application_for_startup(
    app: &AppHandle,
    application: &NativeApplication,
    diagnostics: &AppDiagnostics,
    now_unix: i64,
) -> Result<Bootstrap, CommandError> {
    #[cfg(target_os = "android")]
    {
        app.state::<Arc<nelomai_client_container::ipc::PrivateRuntimeAuthClient>>()
            .owner_request(nelomai_client_container::host::HostRequestV1::RuntimeReady)
            .await
            .map_err(|_| {
                CommandError::from_core(nelomai_client_core::CoreError::AuthRecoveryRequired)
            })?;
        let first_error = match application.bootstrap_without_refresh(now_unix).await {
            Ok(response) => return Ok(response),
            Err(error) => error,
        };
        diagnostics.record_named("startup.auth_recovery.begin", None, None, None);
        // Eligibility comes from the owner and exact runtime admission, not the
        // presentation error. No error callback clears native protected state.
        let owner = app.state::<Arc<nelomai_client_container::ipc::PrivateRuntimeAuthClient>>();
        let recovery = owner.background(nelomai_client_container::ipc::BackgroundAction::Recover);
        // Only a known-not-issued recovery clears its own ticket. A genuinely
        // lost refresh/recovery stays fenced, so this cannot retry its old proof.
        route_android_startup_recovery(
            first_error,
            async {
                recovery
                    .await
                    .map(|_| ())
                    .map_err(|_| nelomai_client_core::CoreError::AuthRecoveryRequired)
            },
            application.bootstrap(now_unix),
        )
        .await
    }
    #[cfg(not(target_os = "android"))]
    {
        let startup = app.state::<Arc<crate::runtime_startup::RuntimeStartup>>();
        let owner = app.state::<Arc<nelomai_client_container::ipc::PrivateRuntimeAuthClient>>();
        startup.ensure_ready(crate::runtime_startup::request_ready(&owner, diagnostics))
            .await.map_err(|error| match error {
                nelomai_client_container::ipc::PrivateError::RefreshPending => CommandError::new(
                    "auth_refresh_pending",
                    "Восстанавливаем соединение с аккаунтом. Повторим автоматически; данные входа сохранены",
                ),
                nelomai_client_container::ipc::PrivateError::RecoveryRequired
                | nelomai_client_container::ipc::PrivateError::Timeout
                | nelomai_client_container::ipc::PrivateError::Service => CommandError::new(
                    "runtime_startup_pending",
                    "Завершается подготовка приложения и предыдущего подключения. Повторим автоматически; данные входа сохранены",
                ),
                _ => CommandError::from_core(CoreError::AuthRecoveryRequired),
            })?;
        application.bootstrap(now_unix).await.map_err(Into::into)
    }
}

#[cfg(any(target_os = "android", test))]
async fn route_android_startup_recovery<T>(
    first_error: ApplicationError,
    recovery: impl std::future::Future<Output = Result<(), CoreError>>,
    ordinary_bootstrap: impl std::future::Future<Output = Result<T, ApplicationError>>,
) -> Result<T, CommandError> {
    if !matches!(
        first_error,
        ApplicationError::Core(CoreError::SignedOut | CoreError::AuthRecoveryRequired)
    ) {
        return Err(first_error.into());
    }
    match recovery.await {
        Ok(()) | Err(CoreError::AuthRecoveryRequired) => {
            ordinary_bootstrap.await.map_err(Into::into)
        }
        Err(error) => Err(CommandError::from_core(error)),
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    code: String,
    message: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsDefenderStatusResponse {
    supported: bool,
    state: String,
    dll_present: bool,
    dll_path: Option<String>,
    detail_code: Option<String>,
    antivirus_products: Vec<WindowsAntivirusProductResponse>,
    antivirus_detail_code: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsAntivirusProductResponse {
    name: String,
    state: String,
    signatures_up_to_date: Option<bool>,
    is_default: Option<bool>,
    is_microsoft_defender: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupStage {
    FrontendMounted,
    FrontendFirstFrame,
    BootstrapSlow,
}

impl StartupStage {
    fn event_name(&self) -> &'static str {
        match self {
            Self::FrontendMounted => "startup.frontend.mounted",
            Self::FrontendFirstFrame => "startup.frontend.first_frame",
            Self::BootstrapSlow => "startup.bootstrap.slow",
        }
    }
}

impl From<ApplicationError> for CommandError {
    fn from(error: ApplicationError) -> Self {
        match error {
            ApplicationError::Storage => Self::new(
                "storage_unavailable",
                "Защищённое хранилище временно недоступно",
            ),
            ApplicationError::Clock => {
                Self::new("clock_unavailable", "Не удалось определить текущее время")
            }
            ApplicationError::RecoveryDeferred => Self::new(
                "recovery_power_deferred",
                "Восстановление продолжится после пробуждения",
            ),
            ApplicationError::Api(error) => Self::from_api(error),
            ApplicationError::Core(error) => Self::from_core(error),
        }
    }
}

impl CommandError {
    pub(crate) fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    fn code(&self) -> &str {
        &self.code
    }

    fn from_api(error: CoreApiError) -> Self {
        match error {
            CoreApiError::Unauthorized => Self::new("signed_out", "Нужно снова войти в приложение"),
            CoreApiError::AccessExpired => Self::new("access_expired", "Срок доступа уже истёк"),
            CoreApiError::Retryable => {
                Self::new("temporarily_unavailable", "Не удалось связаться с панелью")
            }
            CoreApiError::Rejected { code, message, .. } => Self::new(code, message),
        }
    }

    fn from_core(error: CoreError) -> Self {
        match error {
            CoreError::AuthenticationOutcomeUnknown => Self::new("authentication_outcome_unknown", "Исход входа неизвестен; требуется явный повторный вход"),
            CoreError::AuthRecoveryRequired => Self::new("auth_recovery_required", "Требуется восстановление авторизации и безопасное завершение старого подключения"),
            CoreError::SignedOut => Self::new("signed_out", "Нужно снова войти в приложение"),
            CoreError::AccessExpired => Self::new("access_expired", "Срок доступа уже истёк"),
            CoreError::UpdateRequired => Self::new(
                "update_required",
                "Для продолжения необходимо обновить приложение",
            ),
            CoreError::SavedConnectionUnavailable => Self::new(
                "saved_connection_unavailable",
                "Сохранённое подключение сейчас недоступно",
            ),
            CoreError::StartCancelled => {
                Self::new("connection_intent_cancelled", "Подключение отменено")
            }
            CoreError::Storage => Self::new(
                "storage_unavailable",
                "Защищённое хранилище временно недоступно",
            ),
            CoreError::Api(error) => Self::from_api(error),
            CoreError::Tunnel(code) => match code.as_str() {
                "tunnel_handshake_timeout" => Self::new(
                    "tunnel_handshake_timeout",
                    "Stray-сервер не ответил через текущую сеть",
                ),
                code if tunnel_service_error(code) => Self::new(
                    "tunnel_service_unavailable",
                    "Служба подключения недоступна. Повторите действие и разрешите её восстановление",
                ),
                "physical_network_monitor_unavailable" => Self::new(
                    "physical_network_monitor_unavailable",
                    "Не удалось отслеживать смену сети на устройстве",
                ),
                _ => Self::from_route_error(&code).unwrap_or_else(|| {
                    Self::new("tunnel_failed", "Не удалось изменить состояние подключения")
                }),
            },
            CoreError::SplitTunnel(code) => match code.as_str() {
                "split_tunnel_empty_include_selection" => Self::new(
                    "split_tunnel_empty_include_selection",
                    "Выберите хотя бы одно приложение для подключения через VPN",
                ),
                "split_tunnel_apply_failed" => Self::new(
                    "split_tunnel_apply_failed",
                    "Не удалось применить новые настройки. Предыдущее подключение восстановлено",
                ),
                "split_tunnel_stop_failed" => Self::new(
                    "split_tunnel_stop_failed",
                    "Не удалось остановить подключение для применения новых настроек. Повторите позже",
                ),
                "split_tunnel_rollback_failed" => Self::new(
                    "split_tunnel_rollback_failed",
                    "Не удалось восстановить подключение. Запустите его снова",
                ),
                "split_tunnel_address_rule_invalid" => Self::new(
                    "split_tunnel_address_rule_invalid",
                    "Укажите корректный IPv4-адрес, домен или HTTP(S)-ссылку",
                ),
                _ => Self::new(
                    "split_tunnel_policy_unavailable",
                    "Настройки split-tunnel временно недоступны",
                ),
            },
        }
    }

    fn from_tunnel(error: nelomai_client_tunnel::TunnelError) -> Self {
        let code = match error {
            nelomai_client_tunnel::TunnelError::Backend(code) => code,
            nelomai_client_tunnel::TunnelError::InvalidOptions { code } => code.to_string(),
        };
        match code.as_str() {
            "tunnel_handshake_timeout" => Self::new(
                "tunnel_handshake_timeout",
                "Stray-сервер не ответил через текущую сеть",
            ),
            "vpn_permission_denied" => Self::new(
                "vpn_permission_denied",
                "Без разрешения Android подключение невозможно",
            ),
            "tunnel_backend_unavailable" => Self::new(
                "tunnel_backend_unavailable",
                "Система подключения недоступна на этом устройстве",
            ),
            "service_unavailable"
            | "service_timeout"
            | "service_outdated"
            | "unauthorized_client"
            | "truncated_frame" => Self::new(
                "tunnel_service_unavailable",
                "Компоненты подключения не установлены или устарели. Переустановите приложение",
            ),
            "helper_install_cancelled" => {
                Self::new("helper_install_cancelled", "Настройка подключения отменена")
            }
            "helper_authorization_unavailable" => Self::new(
                "helper_authorization_unavailable",
                "Не удалось открыть системный запрос прав администратора",
            ),
            "helper_installer_timeout" => Self::new(
                "helper_installer_timeout",
                "Системная настройка подключения не завершилась вовремя",
            ),
            "helper_resources_unavailable" => Self::new(
                "helper_resources_unavailable",
                "В установленном приложении отсутствуют компоненты подключения",
            ),
            "defender_exclusion_missing" => Self::new(
                "defender_exclusion_missing",
                "Microsoft Defender не исключает компонент AmneziaWG из проверки",
            ),
            "amneziawg_component_missing" => Self::new(
                "amneziawg_component_missing",
                "Антивирус мог удалить или заблокировать компонент AmneziaWG",
            ),
            "antivirus_may_block_amneziawg" => Self::new(
                "antivirus_may_block_amneziawg",
                "Активный сторонний антивирус может блокировать компонент AmneziaWG",
            ),
            "defender_exclusion_repair_cancelled" => Self::new(
                "defender_exclusion_repair_cancelled",
                "Исправление настройки Microsoft Defender отменено",
            ),
            "defender_exclusion_repair_failed" => Self::new(
                "defender_exclusion_repair_failed",
                "Не удалось добавить исключение Microsoft Defender",
            ),
            "physical_network_monitor_unavailable" => Self::new(
                "physical_network_monitor_unavailable",
                "Не удалось отслеживать смену сети на устройстве",
            ),
            _ => Self::from_route_error(&code).unwrap_or_else(|| {
                Self::new(
                    "tunnel_failed",
                    "Не удалось запустить подключение на устройстве",
                )
            }),
        }
    }

    fn from_route_error(code: &str) -> Option<Self> {
        let message = match code {
            "route_conflict" => {
                "Не удалось применить split-tunnel: на устройстве уже существует такой маршрут"
            }
            "route_plan_too_large" | "route_state_too_large" => {
                "Список адресов split-tunnel слишком большой"
            }
            "physical_egress_unavailable" => {
                "Не удалось определить текущее подключение устройства к сети"
            }
            "local_networks_unavailable" => "Не удалось определить локальные сети этого устройства",
            "endpoint_route_unavailable" => {
                "Не удалось безопасно проложить маршрут до Stray-сервера. Переподключите устройство к сети и нажмите «Старт» снова"
            }
            "endpoint_route_lost" => {
                "Сеть изменилась, поэтому Stray остановлен для защиты. Нажмите «Старт» снова"
            }
            "route_state_invalid"
            | "route_state_read_failed"
            | "route_state_write_failed"
            | "route_state_serialize_failed"
            | "route_state_activate_failed"
            | "route_state_remove_failed"
            | "route_add_failed"
            | "route_del_failed"
            | "route_delete_failed"
            | "route_command_failed"
            | "route_command_unavailable"
            | "route_table_unavailable"
            | "ip_command_unavailable" => "Не удалось применить маршруты split-tunnel",
            _ => return None,
        };
        Some(Self::new(code, message))
    }
}

fn tunnel_service_error(code: &str) -> bool {
    matches!(
        code,
        "service_unavailable"
            | "service_timeout"
            | "tunnel_service_unavailable"
            | "tunnel_service_timeout"
            | "service_outdated"
            | "service_stopping"
            | "udp_rebind_failed"
            | "udp_rebind_timeout"
            | "unsupported_protocol"
            | "unauthorized_client"
            | "truncated_frame"
            | "missing_service_version"
    )
}

fn repairable_stop_error(error: &ApplicationError) -> bool {
    matches!(
        error,
        ApplicationError::Core(CoreError::Tunnel(code)) if tunnel_service_error(code)
    )
}

async fn stop_connection(
    app: &AppHandle,
    application: &NativeApplication,
) -> Result<Option<Connection>, CommandError> {
    #[cfg(target_os = "android")]
    {
        let (projection_ticket, service_cancelled) = ANDROID_UI_START_STOP_COORDINATOR
            .dispatch_projected_stop(|| {
                application.signal_start_cancellation();
                app.tunnel_android()
                    .cancel_current_connection_intent()
                    .map_err(|_| {
                        CommandError::new(
                            "android_service_dispatch_unavailable",
                            "Не удалось передать отмену службе подключения",
                        )
                    })
            });
        let cancelled = route_android_connection_stop_with_legacy(
            || {},
            || async move { service_cancelled },
            || async {
                match application.stop().await {
                    Ok(_) | Err(ApplicationError::Core(CoreError::SavedConnectionUnavailable)) => {
                        Ok(())
                    }
                    Err(error) if repairable_stop_error(&error) => {
                        crate::platform::prepare_tunnel_for_stop(app.clone())
                            .await
                            .map_err(CommandError::from_tunnel)?;
                        application
                            .stop()
                            .await
                            .map(|_| ())
                            .map_err(CommandError::from)
                    }
                    Err(error) => Err(error.into()),
                }
            },
        )
        .await;
        let cancelled = match cancelled {
            Ok(cancelled) => cancelled,
            Err(error) => {
                ANDROID_UI_START_STOP_COORDINATOR.finish_projected_action(projection_ticket);
                return Err(error);
            }
        };
        ANDROID_UI_START_STOP_COORDINATOR.commit_projected_action(
            projection_ticket,
            &ANDROID_DESIRED_ACTIVE_PROJECTION,
            cancelled.desired_active,
        );
        return Ok(None);
    }
    #[cfg(not(target_os = "android"))]
    {
        let runtime_cancelled = cancel_desktop_connection_intent(app).await;
        let pending_cancelled = application.signal_start_cancellation();
        let intent_cancelled = runtime_cancelled || pending_cancelled;
        let result = match application.stop().await {
            Ok(connection) => Ok(Some(connection)),
            Err(ApplicationError::Core(CoreError::SavedConnectionUnavailable))
                if intent_cancelled =>
            {
                Ok(None)
            }
            Err(error) if repairable_stop_error(&error) => {
                crate::platform::prepare_tunnel_for_stop(app.clone())
                    .await
                    .map_err(CommandError::from_tunnel)?;
                application.stop().await.map(Some).map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        };
        #[cfg(desktop)]
        if result.is_ok() {
            queue_desktop_tunnel_stopped(app).await;
        }
        result
    }
}

#[cfg(any(target_os = "android", test))]
async fn route_android_connection_stop<F, Fut>(
    service_cancel_current: F,
) -> Result<tauri_plugin_tunnel_android::ConnectionIntentStatusResponse, CommandError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<
        Output = Result<tauri_plugin_tunnel_android::ConnectionIntentStatusResponse, CommandError>,
    >,
{
    service_cancel_current().await
}

#[cfg(any(target_os = "android", test))]
async fn route_android_connection_stop_with_legacy<C, F, Fut, L, LFut>(
    cancel_pending_legacy_start: C,
    service_cancel_current: F,
    legacy_stop: L,
) -> Result<tauri_plugin_tunnel_android::ConnectionIntentStatusResponse, CommandError>
where
    C: FnOnce(),
    F: FnOnce() -> Fut,
    Fut: std::future::Future<
        Output = Result<tauri_plugin_tunnel_android::ConnectionIntentStatusResponse, CommandError>,
    >,
    L: FnOnce() -> LFut,
    LFut: std::future::Future<Output = Result<(), CommandError>>,
{
    cancel_pending_legacy_start();
    let cancelled = route_android_connection_stop(service_cancel_current).await?;
    if cancelled.lease_phase.is_none() {
        legacy_stop().await?;
    }
    Ok(cancelled)
}

pub(crate) async fn stop_for_shutdown(
    app: &AppHandle,
    application: &NativeApplication,
) -> Result<(), CommandError> {
    let runtime_cancelled = cancel_desktop_connection_intent(app).await;
    let pending_cancelled = application.signal_start_cancellation();
    let intent_cancelled = runtime_cancelled || pending_cancelled;
    let state = application.state().await;
    if !shutdown_requires_stop(&state, intent_cancelled) {
        return Ok(());
    }

    let result = match application.stop_for_shutdown().await {
        Ok(_) => Ok(()),
        Err(ApplicationError::Core(CoreError::SavedConnectionUnavailable)) if intent_cancelled => {
            Ok(())
        }
        Err(error) if repairable_stop_error(&error) => {
            crate::platform::prepare_tunnel_for_stop(app.clone())
                .await
                .map_err(CommandError::from_tunnel)?;
            application
                .stop_for_shutdown()
                .await
                .map(|_| ())
                .map_err(Into::into)
        }
        Err(error) => Err(error.into()),
    };
    #[cfg(desktop)]
    if result.is_ok() {
        queue_desktop_tunnel_stopped(app).await;
    }
    result
}

fn shutdown_requires_stop(state: &CoreState, intent_cancelled: bool) -> bool {
    intent_cancelled
        || state.connection.is_some()
        || matches!(
            state.phase,
            Phase::Connected | Phase::Connecting | Phase::Stopping
        )
}

#[cfg(not(target_os = "android"))]
async fn cancel_desktop_connection_intent(app: &AppHandle) -> bool {
    use tauri::Manager;

    let runtime = app
        .state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
        .inner()
        .clone();
    runtime.cancel().await
}

#[cfg(target_os = "android")]
async fn cancel_desktop_connection_intent(_app: &AppHandle) -> bool {
    false
}

#[cfg(desktop)]
fn begin_desktop_tunnel_diagnostics(app: &AppHandle, session_id: &str) {
    use tauri::Manager;

    let diagnostics = app.state::<Arc<AppDiagnostics>>();
    let now = now_unix();
    if let Ok(observation) = diagnostics.observe_automatic_tunnel(Some(session_id), true, now) {
        if observation.interval_started.is_some() {
            diagnostics.begin_automatic_resource_interval(
                &observation,
                crate::resource_usage::ResourceSnapshot::capture(app),
            );
        }
    }
}

#[cfg(desktop)]
async fn queue_desktop_tunnel_stopped(app: &AppHandle) {
    use tauri::Manager;

    let diagnostics = app.state::<Arc<AppDiagnostics>>().inner().clone();
    let tunnel = app
        .state::<Arc<crate::platform::PlatformTunnelController>>()
        .inner()
        .clone();
    let now = now_unix();
    let queued = diagnostics
        .observe_automatic_tunnel(None, false, now)
        .is_ok_and(|observation| observation.seal_pending);
    if !queued {
        return;
    }
    let Ok(Some(seal)) = diagnostics.pending_automatic_seal() else {
        return;
    };
    let helper_log = crate::platform::diagnostic_helper_log(&tunnel).await;
    let resource_snapshot = crate::resource_usage::ResourceSnapshot::capture(app);
    match diagnostics.materialize_automatic_report(&seal, resource_snapshot, helper_log) {
        Ok(true) => diagnostics.record_named(
            "diagnostics.automatic_report_queued",
            Some(&seal.session_id),
            Some(&seal.report_id),
            Some(&seal.trigger),
        ),
        Ok(false) => {}
        Err(error) => diagnostics.record_named(
            "diagnostics.automatic_report_queue_failed",
            Some(&seal.session_id),
            None,
            Some(&error.kind().to_string()),
        ),
    }
}

#[cfg(desktop)]
async fn prepare_desktop_logout(
    app: &AppHandle,
    application: &NativeApplication,
    diagnostics: &AppDiagnostics,
) {
    use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStatus};

    let session_id = application
        .connection_metrics_context()
        .await
        .map(|context| context.session_id);
    let tunnel = app
        .state::<Arc<crate::platform::PlatformTunnelController>>()
        .inner()
        .clone();
    let status = tunnel.status().await;
    let stop_result = if matches!(status, Ok(TunnelStatus::Stopped | TunnelStatus::Failed)) {
        Ok(())
    } else {
        match tunnel.stop().await {
            Err(TunnelError::Backend(code)) if tunnel_service_error(&code) => {
                match crate::platform::prepare_tunnel_for_stop(app.clone()).await {
                    Ok(()) => tunnel.stop().await,
                    Err(error) => Err(error),
                }
            }
            result => result,
        }
    };
    match stop_result {
        Ok(()) => {
            if let Err(error) = application.reset_transport() {
                diagnostics.record_named(
                    "connection.transport_reset_failed",
                    session_id.as_deref(),
                    None,
                    Some(&error.to_string()),
                );
            }
            queue_desktop_tunnel_stopped(app).await;
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                crate::upload_latest_automatic_diagnostics_for_logout(application, diagnostics),
            )
            .await;
        }
        Err(error) => diagnostics.record_named(
            "diagnostics.logout_tunnel_stop_failed",
            session_id.as_deref(),
            None,
            Some(&error.to_string()),
        ),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateResponse {
    phase: &'static str,
    local_stop_pending_cleanup: bool,
    connection: Option<Connection>,
    connection_intent_status: &'static str,
    next_retry_at_unix: Option<i64>,
    warning: Option<String>,
    metrics: Option<ConnectionMetricsResponse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartCommandResponse {
    status: &'static str,
    connection: Option<Connection>,
    next_retry_at_unix: Option<i64>,
}

impl StartCommandResponse {
    pub(crate) fn connected(connection: Connection) -> Self {
        Self {
            status: "connected",
            connection: Some(connection),
            next_retry_at_unix: None,
        }
    }

    pub(crate) fn recovering(next_retry_at_unix: Option<i64>) -> Self {
        Self {
            status: "recovering",
            connection: None,
            next_retry_at_unix,
        }
    }
}

#[cfg(any(target_os = "android", test))]
async fn route_android_app_start<F, Fut, P, PFut>(
    request: tauri_plugin_tunnel_android::BeginConnectionIntentRequest,
    begin: F,
    rust_panel_start: P,
) -> Result<StartCommandResponse, CommandError>
where
    F: FnOnce(tauri_plugin_tunnel_android::BeginConnectionIntentRequest) -> Fut,
    Fut: std::future::Future<
        Output = Result<tauri_plugin_tunnel_android::ConnectionIntentStatusResponse, CommandError>,
    >,
    P: FnOnce() -> PFut,
    PFut: std::future::Future<Output = Result<Connection, CommandError>>,
{
    // Ownership is selected here. Keeping the Rust start collaborator in this boundary makes
    // tests prove that Android never polls it while still exercising the production route.
    let _rust_panel_start = rust_panel_start;
    let acknowledged = begin(request).await?;
    if !android_start_acknowledgement_is_durable(&acknowledged) {
        return Err(CommandError::new(
            "connection_intent_persist_failed",
            "Не удалось сохранить намерение подключения",
        ));
    }
    Ok(StartCommandResponse::recovering(
        acknowledged.next_retry_at_unix,
    ))
}

#[cfg(any(target_os = "android", test))]
async fn route_android_app_start_with_capability<R, RFut, F, Fut, P, PFut>(
    current: &tauri_plugin_tunnel_android::ConnectionIntentStatusResponse,
    capability: Option<&ConnectionIntentCapability>,
    now_unix: i64,
    build_recovery_request: R,
    begin: F,
    rust_panel_start: P,
) -> Result<StartCommandResponse, CommandError>
where
    R: FnOnce() -> RFut,
    RFut: std::future::Future<
        Output = Result<tauri_plugin_tunnel_android::BeginConnectionIntentRequest, CommandError>,
    >,
    F: FnOnce(tauri_plugin_tunnel_android::BeginConnectionIntentRequest) -> Fut,
    Fut: std::future::Future<
        Output = Result<tauri_plugin_tunnel_android::ConnectionIntentStatusResponse, CommandError>,
    >,
    P: FnOnce() -> PFut,
    PFut: std::future::Future<Output = Result<Connection, CommandError>>,
{
    if current.lease_phase.is_none()
        && !nelomai_contracts::allows_new_connection_intent_operation(capability, now_unix)
    {
        return rust_panel_start()
            .await
            .map(StartCommandResponse::connected);
    }
    let request = build_recovery_request().await?;
    route_android_app_start(request, begin, rust_panel_start).await
}

#[cfg(any(target_os = "android", test))]
async fn route_android_logout<E>(
    owner_logout: impl std::future::Future<Output = Result<(), E>>,
) -> Result<(), E> {
    // The broker owns stop/native-handoff/HTTP ordering. Neither the native
    // ownership response nor a scheduler can replace its durable result.
    owner_logout.await
}
#[cfg(any(target_os = "android", test))]
fn android_start_acknowledgement_is_durable(
    acknowledged: &tauri_plugin_tunnel_android::ConnectionIntentStatusResponse,
) -> bool {
    if !acknowledged.desired_active {
        return false;
    }
    matches!(
        (
            acknowledged.lease_phase.as_deref(),
            acknowledged.status.as_str(),
        ),
        (Some("start_pending" | "lease_acquired"), "recovering")
            | (Some("cleanup_pending" | "stale_cleanup"), "stopping")
            | (Some("active_checkpoint"), "none")
    )
}

#[cfg(any(target_os = "android", test))]
async fn route_android_quick_toggle<F, Fut, B, BFut, S, SFut>(
    service_toggle: F,
    rust_bootstrap: B,
    rust_start: S,
) -> Result<tauri_plugin_tunnel_android::ConnectionIntentStatusResponse, CommandError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<
        Output = Result<tauri_plugin_tunnel_android::ConnectionIntentStatusResponse, CommandError>,
    >,
    B: FnOnce() -> BFut,
    BFut: std::future::Future<Output = Result<(), CommandError>>,
    S: FnOnce() -> SFut,
    SFut: std::future::Future<Output = Result<(), CommandError>>,
{
    let (_rust_bootstrap, _rust_start) = (rust_bootstrap, rust_start);
    service_toggle().await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPreferencesResponse {
    close_to_tray_supported: bool,
    close_to_tray: bool,
    dns_provider: DnsProvider,
    personal_tic_egress_mode: EgressMode,
    dynamic_tic_egress_mode: EgressMode,
}

impl AppStateResponse {
    fn new(
        state: CoreState,
        warning: Option<String>,
        metrics: Option<ConnectionMetricsResponse>,
        connection_intent_status: nelomai_client_core::ConnectionIntentStatus,
        next_retry_at_unix: Option<i64>,
    ) -> Self {
        let phase = if connection_intent_status
            == nelomai_client_core::ConnectionIntentStatus::Recovering
            && matches!(
                state.phase,
                Phase::Ready | Phase::Connecting | Phase::Stopping | Phase::ServerUnavailable
            ) {
            "connecting"
        } else {
            phase_name(state.phase)
        };
        Self {
            phase,
            local_stop_pending_cleanup: false,
            connection: state.connection,
            connection_intent_status: connection_intent_status_name(connection_intent_status),
            next_retry_at_unix,
            warning,
            metrics,
        }
    }

    fn with_local_stop_pending_cleanup(mut self, confirmed: bool) -> Self {
        self.local_stop_pending_cleanup = confirmed
            && (matches!(self.phase, "stopping" | "ready")
                || (self.phase == "connecting" && self.connection_intent_status == "recovering"));
        if self.local_stop_pending_cleanup {
            self.metrics = None;
        }
        self
    }
}

fn connection_intent_status_name(
    status: nelomai_client_core::ConnectionIntentStatus,
) -> &'static str {
    match status {
        nelomai_client_core::ConnectionIntentStatus::None => "none",
        nelomai_client_core::ConnectionIntentStatus::Recovering => "recovering",
        nelomai_client_core::ConnectionIntentStatus::BlockedTerminal => "blocked_terminal",
    }
}

async fn current_connection_metrics(
    tracker: &ConnectionMetricsTracker,
    context: Option<&nelomai_client_core::ConnectionMetricsContext>,
) -> Option<ConnectionMetricsResponse> {
    tracker.snapshot(&context?.session_id).await
}

#[cfg(not(target_os = "android"))]
async fn current_connection_intent(
    app: &AppHandle,
    _status_unavailable_fallback: nelomai_client_core::ConnectionIntentStatus,
) -> (nelomai_client_core::ConnectionIntentStatus, Option<i64>) {
    use tauri::Manager;

    let snapshot = app
        .state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
        .snapshot()
        .await;
    (snapshot.status, snapshot.next_retry_at_unix)
}

#[cfg(any(target_os = "android", test))]
fn project_android_connection_intent_status(
    status: Option<(&str, Option<i64>)>,
    status_unavailable_fallback: nelomai_client_core::ConnectionIntentStatus,
) -> (nelomai_client_core::ConnectionIntentStatus, Option<i64>) {
    match status {
        Some(("recovering", next_retry_at_unix)) => (
            nelomai_client_core::ConnectionIntentStatus::Recovering,
            next_retry_at_unix,
        ),
        Some(("blocked_terminal", next_retry_at_unix)) => (
            nelomai_client_core::ConnectionIntentStatus::BlockedTerminal,
            next_retry_at_unix,
        ),
        Some(_) => (nelomai_client_core::ConnectionIntentStatus::None, None),
        None => (status_unavailable_fallback, None),
    }
}

#[cfg(target_os = "android")]
async fn current_connection_intent(
    app: &AppHandle,
    _status_unavailable_fallback: nelomai_client_core::ConnectionIntentStatus,
) -> (nelomai_client_core::ConnectionIntentStatus, Option<i64>) {
    let projection_ticket = ANDROID_UI_START_STOP_COORDINATOR.projection_ticket();
    let status = app.tunnel_android().connection_intent_status().ok();
    let (status_is_current, status_unavailable_fallback) = ANDROID_UI_START_STOP_COORDINATOR
        .finalize_projected_status(
            projection_ticket,
            &ANDROID_DESIRED_ACTIVE_PROJECTION,
            status.as_ref().map(|status| status.desired_active),
        );
    project_android_connection_intent_status(
        status
            .as_ref()
            .filter(|_| status_is_current)
            .map(|status| (status.status.as_str(), status.next_retry_at_unix)),
        status_unavailable_fallback,
    )
}

#[cfg(desktop)]
fn metrics_view_is_visible(app: &AppHandle) -> bool {
    app.get_webview_window("main").is_some_and(|window| {
        window.is_visible().unwrap_or(false) && !window.is_minimized().unwrap_or(false)
    })
}

#[cfg(not(desktop))]
fn metrics_view_is_visible(_app: &AppHandle) -> bool {
    true
}

fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::SignedOut => "signed_out",
        Phase::Authenticating => "authenticating",
        Phase::NeedsPeerBinding => "needs_peer_binding",
        Phase::AccessExpired => "access_expired",
        Phase::Ready => "ready",
        Phase::Measuring => "measuring",
        Phase::Connecting => "connecting",
        Phase::Connected => "connected",
        Phase::Stopping => "stopping",
        Phase::UpdateRequired => "update_required",
        Phase::ServerUnavailable => "server_unavailable",
        Phase::Error => "error",
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginCommandRequest {
    login: String,
    password: String,
    device_name: String,
    #[serde(rename = "platformVersion")]
    _platform_version: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartCommandRequest {
    device_id: String,
    #[serde(default)]
    binding_request: Option<BindPeerRequest>,
    layer: Layer,
    tic_connection_mode: TicConnectionMode,
    route_mode: RouteMode,
    egress_mode: EgressMode,
    #[serde(default = "default_true")]
    allow_alternate: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseCommandRequest {
    lease_id: String,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafePeerBindingResponse {
    api_version: nelomai_contracts::ApiVersion,
    request_id: String,
    binding: Option<PeerBinding>,
}

impl From<PeerBindingResponse> for SafePeerBindingResponse {
    fn from(response: PeerBindingResponse) -> Self {
        Self {
            api_version: response.api_version,
            request_id: response.request_id,
            binding: response.binding,
        }
    }
}

#[tauri::command]
pub async fn app_state(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    metrics: State<'_, Arc<ConnectionMetricsTracker>>,
) -> Result<AppStateResponse, CommandError> {
    if metrics_view_is_visible(&app) {
        metrics.mark_observed().await;
    }
    #[cfg(target_os = "android")]
    let quick_projection_ticket = ANDROID_UI_START_STOP_COORDINATOR.projection_ticket();
    let quick_state_change = app
        .tunnel_android()
        .take_quick_state_change()
        .unwrap_or_default();
    #[cfg(target_os = "android")]
    let quick_projection_applied = ANDROID_UI_START_STOP_COORDINATOR.observe_projected_snapshot(
        quick_projection_ticket,
        &ANDROID_DESIRED_ACTIVE_PROJECTION,
        quick_state_change.changed,
        quick_state_change.desired_active,
    );
    #[cfg(not(target_os = "android"))]
    let quick_projection_applied = true;
    let quick_state_changed = quick_state_change.changed && quick_projection_applied;
    let state = if quick_state_changed && quick_reconcile_is_due(now_unix()) {
        match application.bootstrap(now_unix()).await {
            Ok(response) => {
                #[cfg(desktop)]
                diagnostics.set_automatic_device(&response.device.id);
                provision_android_background_resilient(
                    app.clone(),
                    application.inner().clone(),
                    diagnostics.inner().clone(),
                    response.device.id,
                    response.capabilities,
                )
                .await;
                if app
                    .tunnel_android()
                    .acknowledge_quick_state_change(quick_state_change.revision)
                    .is_ok()
                {
                    clear_quick_reconcile_retry();
                } else {
                    defer_quick_reconcile(now_unix());
                }
                application.state().await
            }
            Err(_) => {
                defer_quick_reconcile(now_unix());
                application.reconcile_external_tunnel_state().await
            }
        }
    } else if quick_state_changed {
        application.reconcile_external_tunnel_state().await
    } else {
        application.state().await
    };
    let warning = application.split_tunnel_warning().await;
    let metrics_context = application.connection_metrics_context().await;
    let current_metrics = current_connection_metrics(&metrics, metrics_context.as_ref()).await;
    let status_unavailable_fallback = android_status_unavailable_fallback();
    let (intent_status, next_retry_at_unix) =
        current_connection_intent(&app, status_unavailable_fallback).await;
    #[cfg(not(target_os = "android"))]
    let local_cleanup = application.local_stop_pending_cleanup().await;
    #[cfg(target_os = "android")]
    let local_cleanup = false;
    Ok(AppStateResponse::new(
        state,
        warning,
        current_metrics,
        intent_status,
        next_retry_at_unix,
    )
    .with_local_stop_pending_cleanup(local_cleanup))
}

#[cfg(target_os = "android")]
fn quick_reconcile_is_due(now_unix: i64) -> bool {
    now_unix >= ANDROID_QUICK_RECONCILE_RETRY_AFTER_UNIX.load(Ordering::Relaxed)
}

#[cfg(not(target_os = "android"))]
fn quick_reconcile_is_due(_now_unix: i64) -> bool {
    true
}

#[cfg(target_os = "android")]
fn defer_quick_reconcile(now_unix: i64) {
    ANDROID_QUICK_RECONCILE_RETRY_AFTER_UNIX.store(
        now_unix.saturating_add(ANDROID_QUICK_RECONCILE_RETRY_SECONDS),
        Ordering::Relaxed,
    );
}

#[cfg(not(target_os = "android"))]
fn defer_quick_reconcile(_now_unix: i64) {}

#[cfg(target_os = "android")]
fn clear_quick_reconcile_retry() {
    ANDROID_QUICK_RECONCILE_RETRY_AFTER_UNIX.store(0, Ordering::Relaxed);
}

#[cfg(not(target_os = "android"))]
fn clear_quick_reconcile_retry() {}

#[tauri::command]
pub fn app_preferences(preferences: State<'_, Arc<AppPreferenceStore>>) -> AppPreferencesResponse {
    let current = preferences.get();
    AppPreferencesResponse {
        close_to_tray_supported: cfg!(desktop),
        close_to_tray: current.close_to_tray,
        dns_provider: current.dns_provider,
        personal_tic_egress_mode: current.personal_tic_egress_mode,
        dynamic_tic_egress_mode: current.dynamic_tic_egress_mode,
    }
}

#[tauri::command]
pub fn app_set_close_to_tray(
    preferences: State<'_, Arc<AppPreferenceStore>>,
    enabled: bool,
) -> Result<AppPreferencesResponse, CommandError> {
    let saved = preferences.set_close_to_tray(enabled).map_err(|_| {
        CommandError::new(
            "preferences_unavailable",
            "Не удалось сохранить настройки приложения",
        )
    })?;
    Ok(AppPreferencesResponse {
        close_to_tray_supported: cfg!(desktop),
        close_to_tray: saved.close_to_tray,
        dns_provider: saved.dns_provider,
        personal_tic_egress_mode: saved.personal_tic_egress_mode,
        dynamic_tic_egress_mode: saved.dynamic_tic_egress_mode,
    })
}

#[tauri::command]
pub fn app_set_dns_provider(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    preferences: State<'_, Arc<AppPreferenceStore>>,
    provider: DnsProvider,
) -> Result<AppPreferencesResponse, CommandError> {
    let saved = preferences.set_dns_provider(provider).map_err(|_| {
        CommandError::new(
            "preferences_unavailable",
            "Не удалось сохранить настройки приложения",
        )
    })?;
    let dns_servers = saved.dns_provider.servers();
    application.set_dns_servers(dns_servers.clone());
    let _ = app
        .tunnel_android()
        .update_quick_dns(tauri_plugin_tunnel_android::DnsServersRequest {
            dns_servers: dns_servers.iter().map(ToString::to_string).collect(),
        });
    Ok(AppPreferencesResponse {
        close_to_tray_supported: cfg!(desktop),
        close_to_tray: saved.close_to_tray,
        dns_provider: saved.dns_provider,
        personal_tic_egress_mode: saved.personal_tic_egress_mode,
        dynamic_tic_egress_mode: saved.dynamic_tic_egress_mode,
    })
}

#[tauri::command]
pub fn app_set_tic_egress_mode(
    preferences: State<'_, Arc<AppPreferenceStore>>,
    connection_mode: TicConnectionMode,
    egress_mode: EgressMode,
) -> Result<AppPreferencesResponse, CommandError> {
    let saved = preferences
        .set_tic_egress_mode(connection_mode, egress_mode)
        .map_err(|_| {
            CommandError::new(
                "preferences_unavailable",
                "Не удалось сохранить настройки приложения",
            )
        })?;
    Ok(AppPreferencesResponse {
        close_to_tray_supported: cfg!(desktop),
        close_to_tray: saved.close_to_tray,
        dns_provider: saved.dns_provider,
        personal_tic_egress_mode: saved.personal_tic_egress_mode,
        dynamic_tic_egress_mode: saved.dynamic_tic_egress_mode,
    })
}

pub(crate) async fn quick_toggle(
    app: &AppHandle,
    application: &NativeApplication,
    skip_probe_refresh: bool,
) -> Result<AppStateResponse, CommandError> {
    #[cfg(target_os = "android")]
    {
        let _ = skip_probe_refresh;
        let (projection_ticket, service_toggle) = ANDROID_UI_START_STOP_COORDINATOR
            .dispatch_projected_toggle(&ANDROID_DESIRED_ACTIVE_PROJECTION, || {
                app.tunnel_android()
                    .toggle_connection_intent()
                    .map_err(|_| {
                        CommandError::new(
                            "android_service_dispatch_unavailable",
                            "Не удалось передать команду службе подключения",
                        )
                    })
            });
        let status = route_android_quick_toggle(
            || async move { service_toggle },
            || async {
                application
                    .bootstrap(now_unix())
                    .await
                    .map(|_| ())
                    .map_err(CommandError::from)
            },
            || async {
                application
                    .start_saved_stray_offline(now_unix())
                    .await
                    .map(|_| ())
                    .map_err(CommandError::from)
            },
        )
        .await;
        let status = match status {
            Ok(status) => status,
            Err(error) => {
                ANDROID_UI_START_STOP_COORDINATOR.finish_projected_action(projection_ticket);
                return Err(error);
            }
        };
        ANDROID_UI_START_STOP_COORDINATOR.commit_projected_action(
            projection_ticket,
            &ANDROID_DESIRED_ACTIVE_PROJECTION,
            status.desired_active,
        );
    }
    #[cfg(not(target_os = "android"))]
    {
        let state = application.state().await;
        let (intent_status, _) =
            current_connection_intent(app, nelomai_client_core::ConnectionIntentStatus::Recovering)
                .await;
        if intent_status != nelomai_client_core::ConnectionIntentStatus::None {
            stop_connection(app, application).await?;
        } else {
            match state.phase {
                Phase::Connected => {
                    stop_connection(app, application).await?;
                }
                Phase::Ready | Phase::Error | Phase::ServerUnavailable => {
                    #[cfg(not(target_os = "android"))]
                    let connection = app
                        .state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
                        .start_or_resume_quick_toggle(skip_probe_refresh, now_unix())
                        .await?
                        .connection;
                    #[cfg(target_os = "android")]
                    let connection: Option<Connection> = {
                        let _ = skip_probe_refresh;
                        let tunnel_options = application
                            .connection_intent_tunnel_options(
                                options.layer,
                                options.route_mode,
                                now_unix(),
                            )
                            .await
                            .map(tauri_plugin_tunnel_android::connection_intent_tunnel_options)
                            .map_err(CommandError::from)?;
                        app.tunnel_android()
                        .begin_connection_intent(
                            tauri_plugin_tunnel_android::BeginConnectionIntentRequest {
                                api_version: tauri_plugin_tunnel_android::TUNNEL_API_VERSION,
                                template:
                                    tauri_plugin_tunnel_android::ConnectionIntentTemplateRequest {
                                        device_id: bootstrap.device.id.clone(),
                                        account_scope: bootstrap.device.id.clone(),
                                        layer: match options.layer {
                                            Layer::Tic => "tic",
                                            Layer::Stray => "stray",
                                        }
                                        .to_string(),
                                        tic_connection_mode: match options.tic_connection_mode {
                                            TicConnectionMode::Personal => "personal",
                                            TicConnectionMode::Dynamic => "dynamic",
                                        }
                                        .to_string(),
                                        route_mode: match options.route_mode {
                                            RouteMode::Standalone => "standalone",
                                            RouteMode::ViaTak => "via_tak",
                                        }
                                        .to_string(),
                                        egress_mode: match options.egress_mode {
                                            EgressMode::Ipv4 => "ipv4",
                                            EgressMode::PreferIpv6 => "prefer_ipv6",
                                        }
                                        .to_string(),
                                        allow_alternate: options.allow_alternate,
                                        sync_binding_preferences: false,
                                        options: tunnel_options,
                                    },
                            },
                        )
                        .map_err(|_| {
                            CommandError::new(
                                "android_service_dispatch_unavailable",
                                "Не удалось передать намерение службе подключения",
                            )
                        })?;
                        None
                    };
                    #[cfg(desktop)]
                    if let Some(connection) = &connection {
                        begin_desktop_tunnel_diagnostics(app, &connection.lease_id);
                    }
                    #[cfg(not(desktop))]
                    let _ = connection;
                }
                Phase::Connecting | Phase::Stopping | Phase::Measuring | Phase::Authenticating => {
                    return Err(CommandError::new(
                        "connection_busy",
                        "Дождитесь завершения текущего действия",
                    ));
                }
                Phase::SignedOut => {
                    return Err(CommandError::new(
                        "signed_out",
                        "Нужно снова войти в приложение",
                    ));
                }
                Phase::NeedsPeerBinding => {
                    return Err(CommandError::new(
                        "peer_binding_required",
                        "Сначала выберите пир в приложении",
                    ));
                }
                Phase::AccessExpired => {
                    return Err(CommandError::new(
                        "access_expired",
                        "Срок доступа уже истёк",
                    ));
                }
                Phase::UpdateRequired => {
                    return Err(CommandError::new(
                        "update_required",
                        "Для продолжения необходимо обновить приложение",
                    ));
                }
            }
        }
    }
    let state = application.state().await;
    let warning = application.split_tunnel_warning().await;
    let metrics = app.state::<Arc<ConnectionMetricsTracker>>();
    let metrics_context = application.connection_metrics_context().await;
    let current_metrics = current_connection_metrics(&metrics, metrics_context.as_ref()).await;
    let (intent_status, next_retry_at_unix) =
        current_connection_intent(app, nelomai_client_core::ConnectionIntentStatus::Recovering)
            .await;
    #[cfg(not(target_os = "android"))]
    let local_cleanup = application.local_stop_pending_cleanup().await;
    #[cfg(target_os = "android")]
    let local_cleanup = false;
    Ok(AppStateResponse::new(
        state,
        warning,
        current_metrics,
        intent_status,
        next_retry_at_unix,
    )
    .with_local_stop_pending_cleanup(local_cleanup))
}

#[tauri::command]
pub async fn app_login(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    split_tunnel_scheduler: State<'_, Arc<SplitTunnelScheduler>>,
    push_registration_scheduler: State<'_, Arc<PushRegistrationScheduler>>,
    updater: State<'_, Arc<NativeUpdater>>,
    request: LoginCommandRequest,
) -> Result<Bootstrap, CommandError> {
    let response = application
        .login(
            LoginParameters {
                login: request.login,
                password: request.password,
                device_name: request.device_name,
            },
            now_unix(),
        )
        .await
        .map_err(CommandError::from)?;
    #[cfg(target_os = "android")]
    app.state::<Arc<nelomai_client_container::ipc::PrivateRuntimeAuthClient>>()
        .owner_request(nelomai_client_container::host::HostRequestV1::RuntimeReady)
        .await
        .map_err(|_| {
            CommandError::from_core(nelomai_client_core::CoreError::AuthRecoveryRequired)
        })?;
    #[cfg(desktop)]
    diagnostics.set_automatic_device(&response.device.id);
    #[cfg(not(target_os = "android"))]
    let _ = app.tunnel_android().clear_background();
    #[cfg(target_os = "android")]
    let (quick_clear_ticket, quick_plan_result) = ANDROID_UI_START_STOP_COORDINATOR
        .dispatch_projected_clear(|| app.tunnel_android().clear_quick_plan());
    #[cfg(not(target_os = "android"))]
    let quick_plan_result = app.tunnel_android().clear_quick_plan();
    #[cfg(target_os = "android")]
    if quick_plan_result.is_ok() {
        ANDROID_UI_START_STOP_COORDINATOR.commit_projected_action(
            quick_clear_ticket,
            &ANDROID_DESIRED_ACTIVE_PROJECTION,
            false,
        );
    } else {
        ANDROID_UI_START_STOP_COORDINATOR.finish_projected_action(quick_clear_ticket);
    }
    #[cfg(not(target_os = "android"))]
    let _ = quick_plan_result;
    provision_android_background_resilient(
        app.clone(),
        application.inner().clone(),
        diagnostics.inner().clone(),
        response.device.id.clone(),
        response.capabilities.clone(),
    )
    .await;
    schedule_startup_split_tunnel_refresh(
        app.clone(),
        application.inner().clone(),
        diagnostics.inner().clone(),
        split_tunnel_scheduler.inner().clone(),
    );
    observe_and_schedule_update(
        application.inner().clone(),
        updater.inner().clone(),
        &response,
    );
    schedule_push_registration(
        app,
        application.inner().clone(),
        push_registration_scheduler.inner().clone(),
    );
    Ok(response)
}

#[tauri::command]
pub async fn app_bootstrap(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    split_tunnel_scheduler: State<'_, Arc<SplitTunnelScheduler>>,
    push_registration_scheduler: State<'_, Arc<PushRegistrationScheduler>>,
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<Bootstrap, CommandError> {
    diagnostics.record_named("startup.bootstrap.begin", None, None, None);
    let bootstrap_started = Instant::now();
    let response = match tokio::time::timeout(
        STARTUP_BOOTSTRAP_TIMEOUT,
        bootstrap_application_for_startup(
            &app,
            application.inner(),
            diagnostics.inner(),
            now_unix(),
        ),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            diagnostics.record_timed_named(
                "startup.bootstrap.failed",
                None,
                None,
                Some(error.code()),
                bootstrap_started.elapsed(),
            );
            return Err(error);
        }
        Err(_) => {
            diagnostics.record_timed_named(
                "startup.bootstrap.failed",
                None,
                None,
                Some("startup_timeout"),
                bootstrap_started.elapsed(),
            );
            return Err(CommandError::new(
                "startup_timeout",
                "Не удалось завершить запуск вовремя. Проверьте сеть и повторите попытку",
            ));
        }
    };
    diagnostics.record_timed_named(
        "startup.bootstrap.ready",
        None,
        Some(&response.request_id),
        None,
        bootstrap_started.elapsed(),
    );
    #[cfg(desktop)]
    diagnostics.set_automatic_device(&response.device.id);
    schedule_startup_split_tunnel_refresh(
        app.clone(),
        application.inner().clone(),
        diagnostics.inner().clone(),
        split_tunnel_scheduler.inner().clone(),
    );
    schedule_android_background_provision(
        app.clone(),
        application.inner().clone(),
        diagnostics.inner().clone(),
        response.device.id.clone(),
        response.capabilities.clone(),
    );
    observe_and_schedule_update(
        application.inner().clone(),
        updater.inner().clone(),
        &response,
    );
    schedule_push_registration(
        app,
        application.inner().clone(),
        push_registration_scheduler.inner().clone(),
    );
    Ok(response)
}

#[tauri::command]
pub fn app_record_startup_stage(diagnostics: State<'_, Arc<AppDiagnostics>>, stage: StartupStage) {
    if matches!(&stage, StartupStage::FrontendFirstFrame) {
        diagnostics.mark_frontend_ready();
    }
    diagnostics.record_named(stage.event_name(), None, None, None);
}

async fn provision_android_background(
    app: &AppHandle,
    application: &NativeApplication,
    device_id: &str,
    capability: Option<&ConnectionIntentCapability>,
) -> Result<(), CommandError> {
    #[cfg(target_os = "android")]
    {
        // The common owner obtains device/capability from its own admitted
        // bootstrap, never from UI-provided install-secret or refresh material.
        let _ = (application, device_id, capability);
        app.state::<Arc<nelomai_client_container::ipc::PrivateRuntimeAuthClient>>()
            .background(nelomai_client_container::ipc::BackgroundAction::Provision)
            .await
            .map_err(|_| {
                CommandError::from_core(nelomai_client_core::CoreError::AuthRecoveryRequired)
            })?;
    }
    #[cfg(not(target_os = "android"))]
    let _ = (app, application, device_id, capability);
    Ok(())
}

async fn provision_android_background_resilient(
    app: AppHandle,
    application: Arc<NativeApplication>,
    diagnostics: Arc<AppDiagnostics>,
    device_id: String,
    capability: Option<ConnectionIntentCapability>,
) {
    let Err(error) = provision_android_background_serialized(
        &app,
        &application,
        &device_id,
        capability.as_ref(),
    )
    .await
    else {
        return;
    };
    diagnostics.record_named(
        "background.provision_failed",
        None,
        None,
        Some(error.code()),
    );

    #[cfg(target_os = "android")]
    tauri::async_runtime::spawn(async move {
        for delay_seconds in [5, 30, 120] {
            tokio::time::sleep(std::time::Duration::from_secs(delay_seconds)).await;
            match provision_android_background_serialized(
                &app,
                &application,
                &device_id,
                capability.as_ref(),
            )
            .await
            {
                Ok(()) => {
                    diagnostics.record_named("background.provision_recovered", None, None, None);
                    return;
                }
                Err(error) => diagnostics.record_named(
                    "background.provision_retry_failed",
                    None,
                    None,
                    Some(error.code()),
                ),
            }
        }
    });

    #[cfg(not(target_os = "android"))]
    let _ = (app, application, device_id, capability);
}

fn schedule_android_background_provision(
    app: AppHandle,
    application: Arc<NativeApplication>,
    diagnostics: Arc<AppDiagnostics>,
    device_id: String,
    capability: Option<ConnectionIntentCapability>,
) {
    tauri::async_runtime::spawn(async move {
        provision_android_background_resilient(
            app,
            application,
            diagnostics,
            device_id,
            capability,
        )
        .await;
    });
}

async fn provision_android_background_serialized(
    app: &AppHandle,
    application: &NativeApplication,
    device_id: &str,
    capability: Option<&ConnectionIntentCapability>,
) -> Result<(), CommandError> {
    #[cfg(target_os = "android")]
    let _guard = ANDROID_BACKGROUND_PROVISION_GATE.lock().await;
    provision_android_background(app, application, device_id, capability).await
}

#[tauri::command]
pub async fn app_peer_options(
    application: State<'_, Arc<NativeApplication>>,
) -> Result<PeerOptions, CommandError> {
    application.peer_options().await.map_err(Into::into)
}

#[tauri::command]
pub async fn app_bind_peer(
    application: State<'_, Arc<NativeApplication>>,
    request: BindPeerRequest,
) -> Result<SafePeerBindingResponse, CommandError> {
    application
        .bind_peer(request)
        .await
        .map(Into::into)
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_unbind_peer(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
) -> Result<SafePeerBindingResponse, CommandError> {
    let response = application
        .unbind_peer()
        .await
        .map_err(CommandError::from)?;
    #[cfg(target_os = "android")]
    let (quick_clear_ticket, quick_plan_result) = ANDROID_UI_START_STOP_COORDINATOR
        .dispatch_projected_clear(|| app.tunnel_android().clear_quick_plan());
    #[cfg(not(target_os = "android"))]
    let quick_plan_result = app.tunnel_android().clear_quick_plan();
    #[cfg(target_os = "android")]
    if quick_plan_result.is_ok() {
        ANDROID_UI_START_STOP_COORDINATOR.commit_projected_action(
            quick_clear_ticket,
            &ANDROID_DESIRED_ACTIVE_PROJECTION,
            false,
        );
    } else {
        ANDROID_UI_START_STOP_COORDINATOR.finish_projected_action(quick_clear_ticket);
    }
    #[cfg(not(target_os = "android"))]
    let _ = quick_plan_result;
    Ok(response.into())
}

#[tauri::command]
pub async fn app_refresh_probes(
    application: State<'_, Arc<NativeApplication>>,
    layer: Layer,
    egress_mode: EgressMode,
) -> Result<ProbeResults, CommandError> {
    application
        .refresh_probes(layer, egress_mode, now_unix())
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_prepare_tunnel(
    app: AppHandle,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    device_id: String,
) -> Result<(), CommandError> {
    match crate::platform::prepare_tunnel(app.clone()).await {
        Ok(()) => {
            diagnostics.record_named("tunnel.prepare_succeeded", None, None, None);
            Ok(())
        }
        Err(error) => {
            let command_error = CommandError::from_tunnel(error);
            diagnostics.record_named(
                "tunnel.prepare_failed",
                None,
                None,
                Some(&command_error.code),
            );
            schedule_start_failure_diagnostics(
                app,
                diagnostics.inner().clone(),
                tauri_plugin_tunnel_android::StartFailureDiagnosticsRequest {
                    device_id,
                    error_code: command_error.code().to_string(),
                },
            );
            Err(command_error)
        }
    }
}

#[tauri::command]
pub async fn app_windows_defender_status(
    diagnostics: State<'_, Arc<AppDiagnostics>>,
) -> Result<WindowsDefenderStatusResponse, CommandError> {
    #[cfg(windows)]
    {
        let status = crate::platform::defender_status(true)
            .await
            .map_err(CommandError::from_tunnel)?;
        record_defender_status(&diagnostics, "windows.defender.checked", &status);
        Ok(defender_status_response(status))
    }
    #[cfg(not(windows))]
    {
        let _ = diagnostics;
        Ok(WindowsDefenderStatusResponse {
            supported: false,
            state: "not_applicable".to_string(),
            dll_present: false,
            dll_path: None,
            detail_code: None,
            antivirus_products: Vec::new(),
            antivirus_detail_code: None,
        })
    }
}

#[tauri::command]
pub async fn app_windows_defender_repair(
    diagnostics: State<'_, Arc<AppDiagnostics>>,
) -> Result<WindowsDefenderStatusResponse, CommandError> {
    #[cfg(windows)]
    {
        let status = match crate::platform::repair_defender_exclusion().await {
            Ok(status) => status,
            Err(error) => {
                let error = CommandError::from_tunnel(error);
                diagnostics.record_named(
                    "windows.defender.repair_failed",
                    None,
                    None,
                    Some(error.code()),
                );
                return Err(error);
            }
        };
        record_defender_status(&diagnostics, "windows.defender.repaired", &status);
        Ok(defender_status_response(status))
    }
    #[cfg(not(windows))]
    {
        let _ = diagnostics;
        Err(CommandError::new(
            "defender_exclusion_unsupported",
            "Microsoft Defender доступен только в Windows",
        ))
    }
}

#[cfg(windows)]
fn defender_status_response(
    status: nelomai_windows_service::DefenderStatus,
) -> WindowsDefenderStatusResponse {
    WindowsDefenderStatusResponse {
        supported: true,
        state: defender_state_name(status.state).to_string(),
        dll_present: status.dll_present,
        dll_path: std::env::current_exe().ok().map(|path| {
            path.with_file_name("amneziawg-tunnel.dll")
                .display()
                .to_string()
        }),
        detail_code: status.detail_code,
        antivirus_products: status
            .antivirus_products
            .into_iter()
            .map(|product| WindowsAntivirusProductResponse {
                name: product.name,
                state: antivirus_product_state_name(product.state).to_string(),
                signatures_up_to_date: product.signatures_up_to_date,
                is_default: product.is_default,
                is_microsoft_defender: product.is_microsoft_defender,
            })
            .collect(),
        antivirus_detail_code: status.antivirus_detail_code,
    }
}

#[cfg(windows)]
fn record_defender_status(
    diagnostics: &AppDiagnostics,
    event: &str,
    status: &nelomai_windows_service::DefenderStatus,
) {
    let active_third_party = status
        .antivirus_products
        .iter()
        .filter(|product| {
            product.state == nelomai_windows_service::AntivirusProductState::On
                && !product.is_microsoft_defender
        })
        .count();
    let code = format!(
        "{}_dll_{}_{}_antivirus_{}_active_third_party_{}_{}",
        defender_state_name(status.state),
        if status.dll_present {
            "present"
        } else {
            "missing"
        },
        status.detail_code.as_deref().unwrap_or("ok"),
        status.antivirus_products.len(),
        active_third_party,
        status.antivirus_detail_code.as_deref().unwrap_or("ok")
    );
    diagnostics.record_named(event, None, None, Some(&code));
}

#[cfg(windows)]
fn antivirus_product_state_name(
    state: nelomai_windows_service::AntivirusProductState,
) -> &'static str {
    use nelomai_windows_service::AntivirusProductState;
    match state {
        AntivirusProductState::On => "on",
        AntivirusProductState::Off => "off",
        AntivirusProductState::Snoozed => "snoozed",
        AntivirusProductState::Expired => "expired",
        AntivirusProductState::Unknown => "unknown",
    }
}

#[cfg(windows)]
fn defender_state_name(state: nelomai_windows_service::DefenderExclusionState) -> &'static str {
    use nelomai_windows_service::DefenderExclusionState;
    match state {
        DefenderExclusionState::Excluded => "excluded",
        DefenderExclusionState::Missing => "missing",
        DefenderExclusionState::Inactive => "inactive",
        DefenderExclusionState::Unavailable => "unavailable",
    }
}

#[cfg(windows)]
pub(crate) async fn ensure_defender_ready_for_awg(
    diagnostics: &AppDiagnostics,
) -> Result<(), ApplicationError> {
    let defender = crate::platform::defender_status(false)
        .await
        .map_err(CoreError::from)?;
    record_defender_status(diagnostics, "windows.defender.before_awg_start", &defender);
    if !defender.dll_present {
        return Err(CoreError::Tunnel("amneziawg_component_missing".to_string()).into());
    }
    if defender.state == nelomai_windows_service::DefenderExclusionState::Missing {
        return Err(CoreError::Tunnel("defender_exclusion_missing".to_string()).into());
    }
    Ok(())
}

#[tauri::command]
pub async fn app_start(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    request: StartCommandRequest,
) -> Result<StartCommandResponse, CommandError> {
    let device_id = request.device_id;
    let failure_device_id = device_id.clone();
    let binding_request = request.binding_request;
    #[cfg(target_os = "android")]
    let android_start_ticket = ANDROID_UI_START_STOP_COORDINATOR.start_ticket();
    #[cfg(not(target_os = "android"))]
    let _ = &application;
    let start_result: Result<StartCommandResponse, CommandError> = async {
        let options = ConnectOptions {
            layer: request.layer,
            tic_connection_mode: request.tic_connection_mode,
            route_mode: request.route_mode,
            egress_mode: request.egress_mode,
            probes: Vec::new(),
            allow_alternate: request.allow_alternate,
        };
        #[cfg(not(target_os = "android"))]
        {
            use tauri::Manager;

            let now = now_unix();
            let runtime = app
                .state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
                .inner()
                .clone();
            runtime
                .start_or_resume_with_initial_preflight(
                    options,
                    device_id.clone(),
                    binding_request,
                    now,
                )
                .await
        }
        #[cfg(target_os = "android")]
        {
            let service_app = app.clone();
            let rust_application = application.inner().clone();
            let response = ANDROID_UI_START_STOP_COORDINATOR
                .run_start(android_start_ticket, || async move {
                    let now = now_unix();
                    let projection_ticket = ANDROID_UI_START_STOP_COORDINATOR.projection_ticket();
                    let current_intent = service_app
                        .tunnel_android()
                        .connection_intent_status()
                        .map_err(|_| {
                            CommandError::new(
                                "android_service_status_unavailable",
                                "Не удалось проверить состояние службы подключения",
                            )
                        })?;
                    ANDROID_UI_START_STOP_COORDINATOR.observe_projected_status(
                        projection_ticket,
                        &ANDROID_DESIRED_ACTIVE_PROJECTION,
                        current_intent.desired_active,
                    );
                    ANDROID_UI_START_STOP_COORDINATOR.ensure_current(android_start_ticket)?;
                    let legacy_start_attempt = current_intent
                        .lease_phase
                        .is_none()
                        .then(|| AndroidLegacyStartAttempt::new(rust_application.clone()));
                    let legacy_start_epoch =
                        legacy_start_attempt.as_ref().map(|attempt| attempt.epoch);
                    let current_bootstrap = if current_intent.lease_phase.is_some() {
                        None
                    } else {
                        let bootstrap = rust_application
                            .bootstrap(now)
                            .await
                            .map_err(CommandError::from)?;
                        if bootstrap.device.id != device_id {
                            return Err(CommandError::new(
                                "device_mismatch",
                                "Подключение запрошено для другого устройства",
                            ));
                        }
                        Some(bootstrap)
                    };
                    let begin_app = service_app.clone();
                    let recovery_application = rust_application.clone();
                    let recovery_device_id = device_id.clone();
                    let recovery_layer = request.layer;
                    let recovery_tic_connection_mode = request.tic_connection_mode;
                    let recovery_route_mode = request.route_mode;
                    let recovery_egress_mode = request.egress_mode;
                    let recovery_allow_alternate = request.allow_alternate;
                    let recovery_sync_binding_preferences = binding_request.is_some();
                    let recovery_capability = current_bootstrap
                        .as_ref()
                        .and_then(|bootstrap| bootstrap.capabilities.as_ref());
                    let response = route_android_app_start_with_capability(
                        &current_intent,
                        recovery_capability,
                        now,
                        move || async move {
                            let tunnel_options = recovery_application
                                .connection_intent_tunnel_options(
                                    recovery_layer,
                                    recovery_route_mode,
                                    now,
                                )
                                .await
                                .map(tauri_plugin_tunnel_android::connection_intent_tunnel_options)
                                .map_err(CommandError::from)?;
                            Ok(tauri_plugin_tunnel_android::BeginConnectionIntentRequest {
                                api_version: tauri_plugin_tunnel_android::TUNNEL_API_VERSION,
                                template:
                                    tauri_plugin_tunnel_android::ConnectionIntentTemplateRequest {
                                        device_id: recovery_device_id.clone(),
                                        account_scope: recovery_device_id,
                                        layer: match recovery_layer {
                                            Layer::Tic => "tic",
                                            Layer::Stray => "stray",
                                        }
                                        .to_string(),
                                        tic_connection_mode: match recovery_tic_connection_mode {
                                            TicConnectionMode::Personal => "personal",
                                            TicConnectionMode::Dynamic => "dynamic",
                                        }
                                        .to_string(),
                                        route_mode: match recovery_route_mode {
                                            RouteMode::Standalone => "standalone",
                                            RouteMode::ViaTak => "via_tak",
                                        }
                                        .to_string(),
                                        egress_mode: match recovery_egress_mode {
                                            EgressMode::Ipv4 => "ipv4",
                                            EgressMode::PreferIpv6 => "prefer_ipv6",
                                        }
                                        .to_string(),
                                        allow_alternate: recovery_allow_alternate,
                                        sync_binding_preferences: recovery_sync_binding_preferences,
                                        options: tunnel_options,
                                    },
                            })
                        },
                        move |request| async move {
                            let (projection_ticket, acknowledged) =
                                ANDROID_UI_START_STOP_COORDINATOR
                                    .run_projected_start_side_effect(
                                        android_start_ticket,
                                        &ANDROID_DESIRED_ACTIVE_PROJECTION,
                                        async move {
                                            begin_app
                                                .tunnel_android()
                                                .begin_connection_intent_async(request)
                                                .await
                                                .map_err(|_| CommandError::new(
                                                    "android_service_dispatch_unavailable",
                                                    "Не удалось передать намерение службе подключения",
                                                ))
                                        },
                                    )
                                    .await?;
                            ANDROID_UI_START_STOP_COORDINATOR.commit_projected_start(
                                android_start_ticket,
                                projection_ticket,
                                &ANDROID_DESIRED_ACTIVE_PROJECTION,
                                acknowledged.desired_active,
                            )?;
                            Ok(acknowledged)
                        },
                        move || async move {
                            let legacy_start_epoch = legacy_start_epoch.ok_or_else(|| {
                                CommandError::new(
                                    "connection_intent_generation_conflict",
                                    "Не удалось подтвердить устаревшее подключение",
                                )
                            })?;
                            ANDROID_UI_START_STOP_COORDINATOR
                                .run_start_side_effect(android_start_ticket, async move {
                                    if let Some(binding_request) = binding_request {
                                        rust_application
                                            .bind_peer(binding_request)
                                            .await
                                            .map_err(CommandError::from)?;
                                    }
                                    rust_application
                                        .start_with_cancellation_epoch(
                                            options,
                                            now,
                                            legacy_start_epoch,
                                        )
                                        .await
                                        .map_err(CommandError::from)
                                })
                                .await
                        },
                    )
                    .await;
                    drop(legacy_start_attempt);
                    response
                })
                .await?;
            Ok(response)
        }
    }
    .await;
    match start_result {
        Ok(response) => {
            #[cfg(desktop)]
            if let Some(connection) = &response.connection {
                begin_desktop_tunnel_diagnostics(&app, &connection.lease_id);
            }
            Ok(response)
        }
        Err(command_error) => {
            schedule_start_failure_diagnostics(
                app,
                diagnostics.inner().clone(),
                tauri_plugin_tunnel_android::StartFailureDiagnosticsRequest {
                    device_id: failure_device_id,
                    error_code: command_error.code().to_string(),
                },
            );
            Err(command_error)
        }
    }
}

#[cfg(any(target_os = "android", test))]
fn android_start_epoch_is_current(expected: u64, current: u64) -> bool {
    expected == current
}

#[tauri::command]
pub async fn app_queue_start_failure_diagnostics(
    app: AppHandle,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    device_id: String,
    error_code: String,
) -> Result<(), CommandError> {
    app.tunnel_android()
        .queue_start_failure_diagnostics_async(
            tauri_plugin_tunnel_android::StartFailureDiagnosticsRequest {
                device_id,
                error_code,
            },
        )
        .await
        .map_err(|_| {
            diagnostics.record_named(
                "diagnostics.start_failure_enqueue_failed",
                None,
                None,
                Some("diagnostics_storage_unavailable"),
            );
            CommandError::new(
                "diagnostics_storage_unavailable",
                "Не удалось сохранить автоматический отчёт",
            )
        })
}

fn schedule_start_failure_diagnostics(
    app: AppHandle,
    diagnostics: Arc<AppDiagnostics>,
    request: tauri_plugin_tunnel_android::StartFailureDiagnosticsRequest,
) {
    #[cfg(target_os = "android")]
    tauri::async_runtime::spawn(async move {
        if app
            .tunnel_android()
            .queue_start_failure_diagnostics_async(request)
            .await
            .is_err()
        {
            diagnostics.record_named(
                "diagnostics.start_failure_enqueue_failed",
                None,
                None,
                Some("diagnostics_storage_unavailable"),
            );
        }
    });

    #[cfg(not(target_os = "android"))]
    let _ = (app, diagnostics, request);
}

#[tauri::command]
pub async fn app_start_saved_stray(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
) -> Result<String, CommandError> {
    #[cfg(windows)]
    ensure_defender_ready_for_awg(&diagnostics).await?;
    #[cfg(not(windows))]
    let _ = &diagnostics;
    refresh_installed_applications_before_start(
        &app,
        &application,
        Layer::Stray,
        RouteMode::Standalone,
    )
    .await?;
    let session_id = application
        .start_saved_stray_offline(now_unix())
        .await
        .map_err(CommandError::from)?;
    #[cfg(desktop)]
    begin_desktop_tunnel_diagnostics(&app, &session_id);
    Ok(session_id)
}

#[tauri::command]
pub async fn app_stop(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
) -> Result<Option<Connection>, CommandError> {
    stop_connection(&app, &application).await
}

#[tauri::command]
pub async fn app_wake_connection_intent(app: AppHandle) -> Result<(), CommandError> {
    #[cfg(not(target_os = "android"))]
    {
        use tauri::Manager;

        app.state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
            .wake_for_network_change()
            .await;
    }
    #[cfg(target_os = "android")]
    let _ = app;
    Ok(())
}

#[tauri::command]
pub async fn app_pin_stray(
    application: State<'_, Arc<NativeApplication>>,
) -> Result<Connection, CommandError> {
    application.pin_stray().await.map_err(Into::into)
}

#[tauri::command]
pub async fn app_unpin_stray(
    application: State<'_, Arc<NativeApplication>>,
    request: LeaseCommandRequest,
) -> Result<Connection, CommandError> {
    application
        .unpin_stray(&request.lease_id, now_unix())
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_send_diagnostics(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    tunnel: State<'_, Arc<crate::platform::PlatformTunnelController>>,
) -> Result<DiagnosticUploadResponse, CommandError> {
    let connection_before = application
        .connection_metrics_context()
        .await
        .map(|context| context.session_id);
    let resource_snapshot = crate::resource_usage::ResourceSnapshot::capture(&app);
    #[cfg(desktop)]
    let helper_log = crate::platform::diagnostic_helper_log(&tunnel).await;
    #[cfg(not(desktop))]
    let helper_log = {
        let _ = &tunnel;
        None
    };
    let connection_after = application
        .connection_metrics_context()
        .await
        .map(|context| context.session_id);
    let connection_lease_id =
        stable_diagnostics_connection_lease(connection_before, connection_after);
    let report = diagnostics
        .build_report_with_helper(
            resource_snapshot,
            helper_log,
            connection_lease_id.as_deref(),
        )
        .map_err(|_| {
            CommandError::new(
                "diagnostics_unavailable",
                "Не удалось подготовить диагностический отчёт",
            )
        })?;
    match application.upload_diagnostics(&report).await {
        Ok(response) => {
            diagnostics.record_named(
                "diagnostics.uploaded",
                None,
                Some(&response.request_id),
                None,
            );
            Ok(response)
        }
        Err(error) => {
            diagnostics.record_named(
                "diagnostics.upload_failed",
                None,
                None,
                Some("upload_failed"),
            );
            Err(error.into())
        }
    }
}

fn stable_diagnostics_connection_lease(
    before: Option<String>,
    after: Option<String>,
) -> Option<String> {
    match (before, after) {
        (Some(before), Some(after)) if before == after => Some(before),
        _ => None,
    }
}

#[tauri::command]
pub async fn app_update_status(
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<UpdateStatusResponse, CommandError> {
    updater.status().await.map_err(update_command_error)
}
#[tauri::command]
pub async fn app_update_refresh(
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<UpdateStatusResponse, CommandError> {
    updater.refresh().await.map_err(update_command_error)
}
#[tauri::command]
pub async fn app_update_set_automatic(
    updater: State<'_, Arc<NativeUpdater>>,
    enabled: bool,
) -> Result<UpdateStatusResponse, CommandError> {
    updater
        .set_automatic(enabled)
        .await
        .map_err(update_command_error)
}
#[tauri::command]
pub async fn app_update_install(
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<UpdateStatusResponse, CommandError> {
    updater.install().await.map_err(update_command_error)
}
#[tauri::command]
pub async fn app_update_restart(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<(), CommandError> {
    if updater.status().await.map_err(update_command_error)?.phase != "ready_to_restart" {
        return Err(CommandError::new(
            "update_not_ready",
            "Обновление ещё не готово к перезапуску",
        ));
    }
    #[cfg(desktop)]
    {
        // Common's verified update barrier already stopped this runtime and the
        // helper before replacing its executable. Re-contacting the old broker
        // hash after replacement cannot provide a new stop acknowledgement.
        let _ = application;
        crate::runtime::native()
            .map_err(|_| update_command_error("common runtime unavailable".into()))?
            .control(crate::runtime::NativeControl::Exit {
                reason: crate::runtime::NativeExitReason::Update,
            })
            .await
            .map_err(|_| update_command_error("common restart failed".into()))?;
        app.exit(0);
        Ok(())
    }
    #[cfg(not(desktop))]
    {
        stop_for_shutdown(&app, &application).await?;
        let _ = app;
        Err(update_command_error("common restart unavailable".into()))
    }
}

fn runtime_switch_error() -> CommandError {
    CommandError::new(
        "runtime_switch_recovery_required",
        "Переключение runtime требует безопасного восстановления",
    )
}

fn runtime_slot_for_selection(use_stable: bool) -> RuntimeSlot {
    if use_stable {
        RuntimeSlot::Stable
    } else {
        RuntimeSlot::Latest
    }
}

#[tauri::command]
pub async fn runtime_status(
    coordinator: State<'_, Arc<RuntimeControls>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
) -> Result<RuntimeSwitchStatusV1, CommandError> {
    let status = coordinator
        .status()
        .await
        .map_err(|_| runtime_switch_error())?;
    diagnostics.record_runtime_status(&status, RuntimeActionSource::Status);
    Ok(status)
}

#[tauri::command]
pub async fn runtime_select(
    coordinator: State<'_, Arc<RuntimeControls>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    use_stable: bool,
) -> Result<RuntimeSwitchStatusV1, CommandError> {
    let current = coordinator
        .status()
        .await
        .map_err(|_| runtime_switch_error())?;
    let desired = runtime_slot_for_selection(use_stable);
    if desired == current.active_slot && current.restart_required() {
        coordinator
            .cancel_pending()
            .await
            .map_err(|_| runtime_switch_error())?;
    } else if desired != current.selected_slot || current.pending_slot.is_some() {
        coordinator
            .request(desired)
            .await
            .map_err(|_| runtime_switch_error())?;
    }
    let status = coordinator
        .status()
        .await
        .map_err(|_| runtime_switch_error())?;
    diagnostics.record_runtime_status(&status, RuntimeActionSource::Selection);
    Ok(status)
}

#[tauri::command]
pub async fn runtime_restart(
    app: AppHandle,
    coordinator: State<'_, Arc<RuntimeControls>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
) -> Result<(), CommandError> {
    let status = coordinator
        .prepare_restart()
        .await
        .map_err(|_| runtime_switch_error())?;
    diagnostics.record_runtime_status(&status, RuntimeActionSource::Restart);
    #[cfg(desktop)]
    crate::runtime::native()
        .map_err(|_| runtime_switch_error())?
        .control(crate::runtime::NativeControl::Exit {
            reason: crate::runtime::NativeExitReason::RuntimeSwitch,
        })
        .await
        .map_err(|_| runtime_switch_error())?;
    // Android's common-owner handoff kills the admitted :runtime PID before
    // releasing the fresh bootstrap gate, so a successful reply is normally
    // unreachable. This is only a post-proof fallback for an unusually late
    // Binder/socket delivery.
    app.exit(0);
    Ok(())
}

#[tauri::command]
pub async fn app_runtime_switch_status(
    coordinator: State<'_, Arc<RuntimeControls>>,
) -> Result<RuntimeSwitchStatusV1, CommandError> {
    coordinator
        .status()
        .await
        .map_err(|_| runtime_switch_error())
}

#[tauri::command]
pub async fn app_runtime_switch_request(
    coordinator: State<'_, Arc<RuntimeControls>>,
    slot: RuntimeSlot,
) -> Result<RuntimeSwitchStatusV1, CommandError> {
    coordinator
        .request(slot)
        .await
        .map_err(|_| runtime_switch_error())?;
    coordinator
        .status()
        .await
        .map_err(|_| runtime_switch_error())
}

#[tauri::command]
pub async fn app_runtime_switch_cancel(
    coordinator: State<'_, Arc<RuntimeControls>>,
) -> Result<RuntimeSwitchStatusV1, CommandError> {
    coordinator
        .cancel_pending()
        .await
        .map_err(|_| runtime_switch_error())?;
    coordinator
        .status()
        .await
        .map_err(|_| runtime_switch_error())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelCapabilitiesResponse {
    platform: &'static str,
    android_api_level: Option<u32>,
    address_split_tunnel: bool,
    application_split_tunnel: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelStateResponse {
    available: bool,
    enabled: bool,
    mode: SplitTunnelMode,
    exclude_local_networks: bool,
    mandatory_excluded_packages: Vec<String>,
    suggested_name_fragments: Vec<String>,
    selected_packages: Vec<String>,
    address_rules: Vec<SplitTunnelAddressRuleResponse>,
    warning: Option<String>,
    capabilities: SplitTunnelCapabilitiesResponse,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelAddressRuleResponse {
    id: i64,
    scope: &'static str,
    kind: &'static str,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelAddressRuleRequest {
    value: String,
    scope: SplitTunnelAddressRuleScope,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledApplicationResponse {
    package_id: String,
    display_name: String,
    system: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelSelectedPackageRequest {
    package_id: String,
    display_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelSaveRequest {
    mode: SplitTunnelMode,
    exclude_local_networks: bool,
    selected_packages: Vec<SplitTunnelSelectedPackageRequest>,
}

impl From<SplitTunnelSaveRequest> for SplitTunnelSettingsUpdate {
    fn from(request: SplitTunnelSaveRequest) -> Self {
        Self {
            mode: request.mode,
            exclude_local_networks: request.exclude_local_networks,
            selected_packages: request
                .selected_packages
                .into_iter()
                .map(|package| SplitTunnelSelectedPackage {
                    package_id: package.package_id,
                    display_name: package.display_name,
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelSaveResponse {
    saved: bool,
    requires_reconnect_confirmation: bool,
    state: SplitTunnelStateResponse,
}

#[tauri::command]
pub async fn app_split_tunnel_state(
    application: State<'_, Arc<NativeApplication>>,
    split_tunnel_scheduler: State<'_, Arc<SplitTunnelScheduler>>,
) -> Result<SplitTunnelStateResponse, CommandError> {
    let _ = split_tunnel_scheduler
        .synchronize(&application, false)
        .await;
    split_tunnel_state(&application).await
}

#[tauri::command]
pub fn app_split_tunnel_installed_applications(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
) -> Result<Vec<InstalledApplicationResponse>, CommandError> {
    refresh_installed_applications(&app, &application)
}

#[tauri::command]
pub async fn app_split_tunnel_save(
    application: State<'_, Arc<NativeApplication>>,
    request: SplitTunnelSaveRequest,
    confirm_reconnect: bool,
) -> Result<SplitTunnelSaveResponse, CommandError> {
    let request = SplitTunnelSettingsUpdate::from(request);
    let reconnect = application
        .split_tunnel_settings_require_reconnect(&request)
        .await
        .map_err(CommandError::from)?;
    if reconnect && !confirm_reconnect {
        return Ok(SplitTunnelSaveResponse {
            saved: false,
            requires_reconnect_confirmation: true,
            state: split_tunnel_state(&application).await?,
        });
    }
    application
        .save_split_tunnel_settings(&request, now_unix())
        .await
        .map_err(CommandError::from)?;
    Ok(SplitTunnelSaveResponse {
        saved: true,
        requires_reconnect_confirmation: false,
        state: split_tunnel_state(&application).await?,
    })
}

#[tauri::command]
pub async fn app_split_tunnel_refresh(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    split_tunnel_scheduler: State<'_, Arc<SplitTunnelScheduler>>,
) -> Result<SplitTunnelStateResponse, CommandError> {
    refresh_installed_applications(&app, &application)?;
    split_tunnel_scheduler
        .synchronize(&application, true)
        .await?;
    split_tunnel_state(&application).await
}

#[tauri::command]
pub async fn app_split_tunnel_add_address_rule(
    application: State<'_, Arc<NativeApplication>>,
    request: SplitTunnelAddressRuleRequest,
) -> Result<SplitTunnelStateResponse, CommandError> {
    application
        .add_split_tunnel_address_rule(
            &SplitTunnelAddressRuleUpdate {
                value: request.value,
                scope: request.scope,
            },
            now_unix(),
        )
        .await
        .map_err(CommandError::from)?;
    split_tunnel_state(&application).await
}

#[tauri::command]
pub async fn app_split_tunnel_remove_address_rule(
    application: State<'_, Arc<NativeApplication>>,
    rule_id: i64,
    scope: SplitTunnelAddressRuleScope,
) -> Result<SplitTunnelStateResponse, CommandError> {
    application
        .remove_split_tunnel_address_rule(rule_id, scope, now_unix())
        .await
        .map_err(CommandError::from)?;
    split_tunnel_state(&application).await
}

#[tauri::command]
pub async fn app_notifications(
    application: State<'_, Arc<NativeApplication>>,
    cursor: Option<i64>,
) -> Result<AppNotificationList, CommandError> {
    application
        .notifications(cursor, 30)
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_notification_read(
    application: State<'_, Arc<NativeApplication>>,
    message_id: i64,
) -> Result<AppNotificationReadResponse, CommandError> {
    application
        .mark_notification_read(message_id)
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_notifications_read_all(
    application: State<'_, Arc<NativeApplication>>,
) -> Result<AppNotificationReadResponse, CommandError> {
    application
        .mark_all_notifications_read()
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_register_push_token(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    push_registration_scheduler: State<'_, Arc<PushRegistrationScheduler>>,
    token: String,
) -> Result<(), CommandError> {
    push_registration_scheduler
        .register_token(&app, &application, &token)
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_logout(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    push_registration_scheduler: State<'_, Arc<PushRegistrationScheduler>>,
) -> Result<(), CommandError> {
    #[cfg(target_os = "android")]
    let logout_result =
        route_android_logout(push_registration_scheduler.logout(application.logout())).await;
    #[cfg(desktop)]
    let logout_result = route_desktop_logout(
        push_registration_scheduler.logout(application.logout()),
        cancel_desktop_connection_intent(&app),
        prepare_desktop_logout(&app, &application, &diagnostics),
    )
    .await;
    #[cfg(all(not(desktop), not(target_os = "android")))]
    let logout_result = push_registration_scheduler
        .logout(application.logout())
        .await;
    #[cfg(target_os = "android")]
    let (quick_clear_ticket, quick_plan_result) = ANDROID_UI_START_STOP_COORDINATOR
        .dispatch_projected_clear(|| app.tunnel_android().clear_quick_plan());
    #[cfg(not(target_os = "android"))]
    let quick_plan_result = app.tunnel_android().clear_quick_plan();
    #[cfg(not(target_os = "android"))]
    let background_result = app.tunnel_android().clear_background();

    if let Err(error) = logout_result {
        #[cfg(target_os = "android")]
        ANDROID_UI_START_STOP_COORDINATOR.finish_projected_action(quick_clear_ticket);
        return Err(CommandError::from(error));
    }
    #[cfg(desktop)]
    diagnostics.clear_automatic_device();
    #[cfg(not(desktop))]
    let _ = &diagnostics;
    if quick_plan_result.is_err() {
        #[cfg(target_os = "android")]
        ANDROID_UI_START_STOP_COORDINATOR.finish_projected_action(quick_clear_ticket);
        return Err(CommandError::new(
            "quick_state_persist_failed",
            "Не удалось очистить данные быстрого подключения",
        ));
    }
    #[cfg(target_os = "android")]
    ANDROID_UI_START_STOP_COORDINATOR.commit_projected_action(
        quick_clear_ticket,
        &ANDROID_DESIRED_ACTIVE_PROJECTION,
        false,
    );
    #[cfg(not(target_os = "android"))]
    background_result.map_err(|_| {
        CommandError::new(
            "background_storage_unavailable",
            "Не удалось очистить данные фонового подключения",
        )
    })?;
    Ok(())
}

#[cfg(desktop)]
async fn route_desktop_logout<E>(
    owner: impl std::future::Future<Output = Result<(), E>>,
    cancel: impl std::future::Future<Output = bool>,
    prepare: impl std::future::Future<Output = ()>,
) -> Result<(), E> {
    // Enter the protected owner before any scheduler/native/diagnostic waits.
    // A later helper retry cannot turn an owner physical-stop error into ACK.
    let result = owner.await;
    cancel.await;
    prepare.await;
    result
}

fn observe_and_schedule_update(
    application: Arc<NativeApplication>,
    updater: Arc<NativeUpdater>,
    bootstrap: &Bootstrap,
) {
    let _ = (application, bootstrap);
    tauri::async_runtime::spawn(async move {
        let _ = updater.refresh().await;
    });
}

fn schedule_push_registration(
    app: AppHandle,
    application: Arc<NativeApplication>,
    scheduler: Arc<PushRegistrationScheduler>,
) {
    tauri::async_runtime::spawn(async move {
        scheduler.synchronize(&app, &application).await;
    });
}

async fn split_tunnel_state(
    application: &NativeApplication,
) -> Result<SplitTunnelStateResponse, CommandError> {
    let capabilities = application
        .split_tunnel_capabilities()
        .await
        .map_err(CommandError::from)?;
    let warning = application.split_tunnel_warning().await;
    let policy = application
        .cached_split_tunnel_policy()
        .map_err(CommandError::from)?;
    Ok(match policy {
        Some(policy) => SplitTunnelStateResponse {
            available: true,
            enabled: policy.enabled,
            mode: policy.mode,
            exclude_local_networks: policy.exclude_local_networks,
            mandatory_excluded_packages: policy.mandatory_excluded_packages,
            suggested_name_fragments: policy.suggested_name_fragments,
            selected_packages: policy.selected_packages,
            address_rules: policy
                .address_rules
                .into_iter()
                .map(|rule| SplitTunnelAddressRuleResponse {
                    id: rule.id,
                    scope: match rule.scope {
                        SplitTunnelAddressRuleScope::ThisDevice => "this_device",
                        SplitTunnelAddressRuleScope::AllDevices => "all_devices",
                    },
                    kind: match rule.kind {
                        nelomai_contracts::SplitTunnelAddressRuleKind::Ipv4 => "ipv4",
                        nelomai_contracts::SplitTunnelAddressRuleKind::Domain => "domain",
                    },
                    value: rule.value,
                })
                .collect(),
            warning,
            capabilities: capabilities.into(),
        },
        None => SplitTunnelStateResponse {
            available: false,
            enabled: false,
            mode: SplitTunnelMode::ExcludeSelected,
            exclude_local_networks: true,
            mandatory_excluded_packages: Vec::new(),
            suggested_name_fragments: Vec::new(),
            selected_packages: Vec::new(),
            address_rules: Vec::new(),
            warning,
            capabilities: capabilities.into(),
        },
    })
}

impl From<TunnelCapabilities> for SplitTunnelCapabilitiesResponse {
    fn from(capabilities: TunnelCapabilities) -> Self {
        Self {
            platform: match capabilities.platform {
                TunnelPlatform::Android => "android",
                TunnelPlatform::Windows => "windows",
                TunnelPlatform::Linux => "linux",
                TunnelPlatform::Macos => "macos",
                TunnelPlatform::Unknown => "unknown",
            },
            android_api_level: capabilities.android_api_level,
            address_split_tunnel: capabilities.address_split_tunnel,
            application_split_tunnel: capabilities.application_split_tunnel,
        }
    }
}

fn refresh_installed_applications(
    app: &AppHandle,
    application: &NativeApplication,
) -> Result<Vec<InstalledApplicationResponse>, CommandError> {
    let response = app.tunnel_android().installed_applications().map_err(|_| {
        CommandError::new(
            "installed_applications_unavailable",
            "Не удалось получить список приложений",
        )
    })?;
    application.set_split_tunnel_installed_packages(
        response
            .applications
            .iter()
            .map(|application| SplitTunnelSelectedPackage {
                package_id: application.package_id.clone(),
                display_name: application.display_name.clone(),
            })
            .collect(),
    );
    Ok(response
        .applications
        .into_iter()
        .map(|application| InstalledApplicationResponse {
            package_id: application.package_id,
            display_name: application.display_name,
            system: application.system,
        })
        .collect())
}

fn schedule_startup_split_tunnel_refresh(
    app: AppHandle,
    application: Arc<NativeApplication>,
    diagnostics: Arc<AppDiagnostics>,
    scheduler: Arc<SplitTunnelScheduler>,
) {
    tauri::async_runtime::spawn(async move {
        #[cfg(target_os = "android")]
        {
            diagnostics.record_named("startup.application_inventory.scheduled", None, None, None);
            let inventory_app = app.clone();
            let inventory_application = application.clone();
            let inventory_diagnostics = diagnostics.clone();
            let inventory_refreshed = match tauri::async_runtime::spawn_blocking(move || {
                let started = Instant::now();
                match refresh_installed_applications(&inventory_app, &inventory_application) {
                    Ok(applications) => {
                        inventory_diagnostics.record_timed_named(
                            "startup.application_inventory.completed",
                            None,
                            None,
                            Some(&format!("applications={}", applications.len())),
                            started.elapsed(),
                        );
                        true
                    }
                    Err(error) => {
                        inventory_diagnostics.record_timed_named(
                            "startup.application_inventory.failed",
                            None,
                            None,
                            Some(error.code()),
                            started.elapsed(),
                        );
                        false
                    }
                }
            })
            .await
            {
                Ok(refreshed) => refreshed,
                Err(_) => {
                    diagnostics.record_named(
                        "startup.application_inventory.failed",
                        None,
                        None,
                        Some("worker_unavailable"),
                    );
                    false
                }
            };
            if !inventory_refreshed {
                return;
            }
        }
        #[cfg(not(target_os = "android"))]
        let _ = (app, diagnostics);
        let _ = scheduler.synchronize(&application, false).await;
    });
}

pub(crate) async fn refresh_installed_applications_before_start(
    app: &AppHandle,
    application: &NativeApplication,
    layer: Layer,
    route_mode: RouteMode,
) -> Result<(), ApplicationError> {
    let capabilities = application.split_tunnel_capabilities().await?;
    let policy = application.cached_split_tunnel_policy()?;
    let inventory_required = capabilities.application_split_tunnel
        && policy.as_ref().is_some_and(|policy| {
            split_tunnel_active(SplitTunnelContext {
                global_enabled: policy.enabled,
                platform: capabilities.platform,
                android_api_level: capabilities.android_api_level,
                layer,
                route_mode,
            })
        });
    if inventory_required {
        let applications = refresh_installed_applications(app, application).map_err(|_| {
            ApplicationError::Core(CoreError::Api(CoreApiError::Rejected {
                code: "installed_applications_unavailable".to_string(),
                message: "Не удалось получить список приложений".to_string(),
                retry_after_seconds: None,
            }))
        })?;
        if applications.is_empty() {
            return Err(ApplicationError::Core(CoreError::Api(
                CoreApiError::Rejected {
                    code: "installed_applications_unavailable".to_string(),
                    message: "Не удалось получить список приложений".to_string(),
                    retry_after_seconds: None,
                },
            )));
        }
    } else {
        let _ = refresh_installed_applications(app, application);
    }
    Ok(())
}

fn update_command_error(error: String) -> CommandError {
    CommandError::new("update_failed", update_error_message(&error))
}

fn update_error_message(error: &str) -> &'static str {
    if error.contains("backend is unavailable") {
        "На этом устройстве обновление устанавливается вручную"
    } else if error.contains("install_permission_denied") {
        "Разрешите Nelomai устанавливать обновления и повторите попытку"
    } else if error.contains("preference") {
        "Не удалось сохранить настройки обновлений"
    } else {
        "Не удалось установить обновление"
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or_default()
}

#[cfg(target_os = "android")]
pub(crate) fn current_platform() -> Platform {
    Platform::Android
}

#[cfg(windows)]
pub(crate) fn current_platform() -> Platform {
    Platform::Windows
}

#[cfg(target_os = "macos")]
pub(crate) fn current_platform() -> Platform {
    Platform::Macos
}

#[cfg(target_os = "linux")]
pub(crate) fn current_platform() -> Platform {
    Platform::Linux
}

#[cfg(test)]
mod tests {
    #[test]
    fn runtime_selection_boolean_maps_only_to_the_verified_slot_enum() {
        assert_eq!(runtime_slot_for_selection(false), RuntimeSlot::Latest);
        assert_eq!(runtime_slot_for_selection(true), RuntimeSlot::Stable);
    }

    #[tokio::test]
    async fn android_startup_owner_rejection_never_falls_through_after_logout_or_access_expiry() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for rejection in [CoreError::StartCancelled, CoreError::AccessExpired] {
            let fallbacks = AtomicUsize::new(0);
            let result = route_android_startup_recovery(
                ApplicationError::Core(CoreError::AuthRecoveryRequired),
                async { Err(rejection) },
                async {
                    fallbacks.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ApplicationError>(42)
                },
            )
            .await;
            assert!(result.is_err());
            assert_eq!(fallbacks.load(Ordering::SeqCst), 0);
        }
        let entered = AtomicUsize::new(0);
        let result = route_android_startup_recovery(
            ApplicationError::Core(CoreError::Api(CoreApiError::Retryable)),
            async {
                entered.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            async {
                entered.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ApplicationError>(42)
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(entered.load(Ordering::SeqCst), 0);
    }
    use super::*;
    use nelomai_contracts::{ApiVersion, LeaseStatus, PeerBinding};

    #[cfg(desktop)]
    #[tokio::test]
    async fn desktop_logout_enters_owner_before_native_prelude_and_retains_stop_error() {
        let entered = std::sync::atomic::AtomicBool::new(false);
        let release = tokio::sync::Notify::new();
        let result = route_desktop_logout(
            async {
                entered.store(true, std::sync::atomic::Ordering::SeqCst);
                Err::<(), _>("physical_stop_failed")
            },
            async {
                assert!(
                    entered.load(std::sync::atomic::Ordering::SeqCst),
                    "native cancel must follow owner cancellation"
                );
                false
            },
            async {
                release.notified().await;
            },
        );
        tokio::pin!(result);
        assert!(tokio::time::timeout(Duration::from_millis(30), &mut result)
            .await
            .is_err());
        assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
        release.notify_one();
        assert_eq!(result.await, Err("physical_stop_failed"));
    }

    fn background_capability_snapshot(
        revision: i64,
        enabled: bool,
        expires_at_unix: i64,
    ) -> AndroidBackgroundCapabilitySnapshot {
        AndroidBackgroundCapabilitySnapshot {
            revision,
            enabled,
            expires_at: if enabled {
                "2099-01-01T00:00:00Z".to_string()
            } else {
                ANDROID_DISABLED_CAPABILITY_EXPIRES_AT.to_string()
            },
            expires_at_unix,
        }
    }

    #[test]
    fn manual_diagnostics_uses_only_an_unchanged_connection_lease() {
        assert_eq!(
            stable_diagnostics_connection_lease(
                Some("lease-1".to_string()),
                Some("lease-1".to_string()),
            ),
            Some("lease-1".to_string()),
        );
        assert_eq!(
            stable_diagnostics_connection_lease(
                Some("lease-1".to_string()),
                Some("lease-2".to_string()),
            ),
            None,
        );
        assert_eq!(
            stable_diagnostics_connection_lease(Some("lease-1".to_string()), None),
            None,
        );
        assert_eq!(
            stable_diagnostics_connection_lease(None, Some("lease-1".to_string())),
            None,
        );
    }

    #[test]
    fn binding_response_never_serializes_wireguard_configuration() {
        let response = SafePeerBindingResponse::from(PeerBindingResponse {
            api_version: ApiVersion::V1,
            request_id: "request-1".to_string(),
            binding: None::<PeerBinding>,
            configuration: Some("PrivateKey = secret".to_string()),
        });

        let json = serde_json::to_string(&response).unwrap();

        assert!(!json.contains("PrivateKey"));
        assert!(!json.contains("configuration"));
    }

    #[test]
    fn connection_intent_state_projection_masks_only_recovering_as_connecting() {
        let recovering = AppStateResponse::new(
            CoreState {
                phase: Phase::ServerUnavailable,
                connection: None,
            },
            None,
            None,
            nelomai_client_core::ConnectionIntentStatus::Recovering,
            Some(1_700_000_123),
        );
        let value = serde_json::to_value(recovering).unwrap();
        assert_eq!(value["phase"], "connecting");
        assert_eq!(value["connectionIntentStatus"], "recovering");
        assert_eq!(value["nextRetryAtUnix"], 1_700_000_123_i64);

        let blocked = AppStateResponse::new(
            CoreState {
                phase: Phase::Error,
                connection: None,
            },
            None,
            None,
            nelomai_client_core::ConnectionIntentStatus::BlockedTerminal,
            None,
        );
        let value = serde_json::to_value(blocked).unwrap();
        assert_eq!(value["phase"], "error");
        assert_eq!(value["connectionIntentStatus"], "blocked_terminal");
        assert!(value["nextRetryAtUnix"].is_null());
        assert_eq!(value["localStopPendingCleanup"], false);
    }

    #[test]
    fn local_stop_projection_preserves_cleanup_and_recovery_intent() {
        use nelomai_client_core::ConnectionIntentStatus;
        for (phase, intent, confirmed, expected) in [
            (Phase::Stopping, ConnectionIntentStatus::None, true, true),
            (Phase::Ready, ConnectionIntentStatus::None, true, true),
            (Phase::Stopping, ConnectionIntentStatus::None, false, false),
            (Phase::Connected, ConnectionIntentStatus::None, true, false),
            (Phase::SignedOut, ConnectionIntentStatus::None, true, false),
            (
                Phase::Stopping,
                ConnectionIntentStatus::Recovering,
                true,
                true,
            ),
        ] {
            let response = AppStateResponse::new(
                CoreState {
                    phase,
                    connection: None,
                },
                None,
                None,
                intent,
                None,
            )
            .with_local_stop_pending_cleanup(confirmed);
            assert_eq!(response.local_stop_pending_cleanup, expected);
            assert_eq!(
                response.connection_intent_status,
                connection_intent_status_name(intent)
            );
            if expected {
                assert!(matches!(
                    response.phase,
                    "stopping" | "ready" | "connecting"
                ));
                assert!(response.metrics.is_none());
            }
        }
    }

    #[test]
    fn unavailable_android_service_preserves_recovery_without_a_confirmed_quick_stop() {
        let projection = AndroidDesiredActiveProjection::new();
        let fallback = projection.status_unavailable_fallback();
        assert_eq!(
            project_android_connection_intent_status(None, fallback),
            (
                nelomai_client_core::ConnectionIntentStatus::Recovering,
                None,
            ),
        );
    }

    #[test]
    fn confirmed_android_stop_remains_idle_across_status_failures() {
        let projection = AndroidDesiredActiveProjection::new();
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::Recovering,
        );

        projection.observe_snapshot(true, Some(false));
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::None,
        );
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::None,
        );

        projection.observe_snapshot(false, None);
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::None,
        );

        projection.observe_snapshot(true, None);
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::Recovering,
        );

        projection.observe_confirmed(true);
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::Recovering,
        );
    }

    #[test]
    fn confirmed_android_quick_stop_clears_an_unavailable_service_status() {
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(false);
        let fallback = projection.status_unavailable_fallback();
        assert_eq!(
            project_android_connection_intent_status(None, fallback),
            (nelomai_client_core::ConnectionIntentStatus::None, None),
        );
        assert_eq!(
            project_android_connection_intent_status(
                Some(("recovering", Some(42))),
                nelomai_client_core::ConnectionIntentStatus::None,
            ),
            (
                nelomai_client_core::ConnectionIntentStatus::Recovering,
                Some(42),
            ),
        );
        assert_eq!(
            project_android_connection_intent_status(
                Some(("blocked_terminal", None)),
                nelomai_client_core::ConnectionIntentStatus::None,
            ),
            (
                nelomai_client_core::ConnectionIntentStatus::BlockedTerminal,
                None,
            ),
        );
    }

    #[test]
    fn connection_intent_start_response_distinguishes_recovery_from_success() {
        let value = serde_json::to_value(StartCommandResponse::recovering(Some(42))).unwrap();
        assert_eq!(value["status"], "recovering");
        assert!(value["connection"].is_null());
        assert_eq!(value["nextRetryAtUnix"], 42);
    }

    #[test]
    fn shutdown_stops_a_blocked_connection_even_after_core_enters_error() {
        assert!(shutdown_requires_stop(
            &CoreState {
                phase: Phase::Error,
                connection: None,
            },
            true,
        ));
    }

    #[test]
    fn split_tunnel_command_models_use_camel_case_without_application_icons() {
        let request: SplitTunnelSaveRequest = serde_json::from_value(serde_json::json!({
            "mode": "exclude_selected",
            "excludeLocalNetworks": true,
            "selectedPackages": [{
                "packageId": "com.example.browser",
                "displayName": "Browser"
            }]
        }))
        .unwrap();
        let update = SplitTunnelSettingsUpdate::from(request);
        assert_eq!(update.mode, SplitTunnelMode::ExcludeSelected);
        assert!(update.exclude_local_networks);
        assert_eq!(
            update.selected_packages[0].package_id,
            "com.example.browser"
        );

        let response = InstalledApplicationResponse {
            package_id: "com.example.browser".to_string(),
            display_name: "Browser".to_string(),
            system: false,
        };
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["packageId"], "com.example.browser");
        assert!(value.get("icon").is_none());
    }

    #[test]
    fn route_errors_do_not_look_like_a_missing_tunnel_service() {
        let error = CommandError::from_core(CoreError::Tunnel("route_conflict".to_string()));

        assert_eq!(error.code, "route_conflict");
        assert!(error.message.contains("маршрут"));
        assert!(!error.message.contains("Переустановите"));

        let endpoint =
            CommandError::from_core(CoreError::Tunnel("endpoint_route_lost".to_string()));
        assert_eq!(endpoint.code, "endpoint_route_lost");
        assert!(endpoint.message.contains("остановлен для защиты"));

        let handshake =
            CommandError::from_core(CoreError::Tunnel("tunnel_handshake_timeout".to_string()));
        assert_eq!(handshake.code, "tunnel_handshake_timeout");
        assert!(handshake.message.contains("Stray-сервер"));
    }

    #[test]
    fn split_tunnel_stop_failure_keeps_its_actionable_error() {
        let error = CommandError::from_core(CoreError::SplitTunnel(
            "split_tunnel_stop_failed".to_string(),
        ));

        assert_eq!(error.code, "split_tunnel_stop_failed");
        assert!(error.message.contains("остановить подключение"));
    }

    #[test]
    fn tunnel_service_failures_are_repairable_before_stop_retry() {
        for code in [
            "service_unavailable",
            "service_outdated",
            "udp_rebind_failed",
            "udp_rebind_timeout",
            "service_stopping",
            "unsupported_protocol",
            "unauthorized_client",
            "truncated_frame",
            "missing_service_version",
        ] {
            let error = ApplicationError::Core(CoreError::Tunnel(code.to_string()));
            assert!(repairable_stop_error(&error), "{code}");
        }
        let route_error = ApplicationError::Core(CoreError::Tunnel("route_conflict".to_string()));
        assert!(!repairable_stop_error(&route_error));
    }

    #[test]
    fn udp_rebind_failures_keep_the_service_recovery_message() {
        for code in ["udp_rebind_failed", "udp_rebind_timeout"] {
            let error = CommandError::from_core(CoreError::Tunnel(code.to_string()));

            assert_eq!(error.code, "tunnel_service_unavailable", "{code}");
            assert!(error.message.contains("Повторите действие"), "{code}");
        }
    }

    #[test]
    fn startup_diagnostics_accept_only_known_frontend_stages() {
        let stage: StartupStage = serde_json::from_str("\"frontend_first_frame\"").unwrap();
        assert_eq!(stage.event_name(), "startup.frontend.first_frame");
        assert!(serde_json::from_str::<StartupStage>("\"arbitrary_event\"").is_err());
    }

    #[test]
    fn enabled_recovery_with_an_expired_device_token_uses_ui_authenticated_provision() {
        let status = tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse {
            configured: true,
            credential_revision: 7,
            mutation_ready: true,
            mutation_pending: false,
            capability_revision: 1,
            capability_enabled: true,
            capability_expires_at_unix: Some(200),
            device_id: Some("device-1".to_string()),
            expires_at_unix: Some(100),
        };

        assert_eq!(
            android_background_provision_mode(
                &status,
                "device-1",
                &background_capability_snapshot(1, true, 200),
                150,
            ),
            AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase,
        );
    }

    #[test]
    fn stored_enabled_capability_prevents_stale_desired_legacy_provisioning() {
        let status = tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse {
            configured: true,
            credential_revision: 7,
            mutation_ready: true,
            mutation_pending: false,
            capability_revision: 1,
            capability_enabled: true,
            capability_expires_at_unix: Some(200),
            device_id: Some("device-1".to_string()),
            expires_at_unix: Some(100),
        };

        assert_eq!(
            android_background_provision_mode(
                &status,
                "device-1",
                &background_capability_snapshot(2, false, 1),
                150,
            ),
            AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase,
        );
    }

    #[test]
    fn pending_activation_is_replayed_even_while_the_old_local_token_looks_fresh() {
        let status = tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse {
            configured: true,
            credential_revision: 8,
            mutation_ready: true,
            mutation_pending: true,
            capability_revision: 1,
            capability_enabled: true,
            capability_expires_at_unix: Some(300),
            device_id: Some("device-1".to_string()),
            expires_at_unix: Some(2_000_000),
        };

        assert_eq!(
            android_background_provision_mode(
                &status,
                "device-1",
                &background_capability_snapshot(1, true, 300),
                150,
            ),
            AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase,
        );
    }

    #[test]
    fn expired_capability_with_a_fresh_device_token_only_refreshes_the_snapshot() {
        let status = tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse {
            configured: true,
            credential_revision: 9,
            mutation_ready: true,
            mutation_pending: false,
            capability_revision: 1,
            capability_enabled: true,
            capability_expires_at_unix: Some(100),
            device_id: Some("device-1".to_string()),
            expires_at_unix: Some(2_000_000),
        };

        assert_eq!(
            android_background_provision_mode(
                &status,
                "device-1",
                &background_capability_snapshot(2, true, 300),
                150,
            ),
            AndroidBackgroundProvisionMode::RefreshStoredCapability,
        );
    }

    #[test]
    fn newer_same_enabled_capability_refreshes_the_android_snapshot() {
        let status = tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse {
            configured: true,
            credential_revision: 9,
            mutation_ready: true,
            mutation_pending: false,
            capability_revision: 10,
            capability_enabled: true,
            capability_expires_at_unix: Some(200),
            device_id: Some("device-1".to_string()),
            expires_at_unix: Some(2_000_000),
        };
        let desired = AndroidBackgroundCapabilitySnapshot {
            revision: 11,
            enabled: true,
            expires_at: "1970-01-01T00:05:00Z".to_string(),
            expires_at_unix: 300,
        };

        assert_eq!(
            android_background_provision_mode(&status, "device-1", &desired, 150),
            AndroidBackgroundProvisionMode::RefreshStoredCapability,
        );
    }

    #[test]
    fn changed_enabled_capability_expiry_refreshes_the_android_snapshot() {
        let status = tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse {
            configured: true,
            credential_revision: 9,
            mutation_ready: true,
            mutation_pending: false,
            capability_revision: 10,
            capability_enabled: true,
            capability_expires_at_unix: Some(200),
            device_id: Some("device-1".to_string()),
            expires_at_unix: Some(2_000_000),
        };
        let desired = android_background_capability_snapshot(
            Some(&ConnectionIntentCapability {
                revision: 10,
                expires_at: "1970-01-01T00:05:00Z".to_string(),
                connection_intent_recovery_v1: true,
            }),
            150,
        );

        assert_eq!(
            android_background_provision_mode(&status, "device-1", &desired, 150),
            AndroidBackgroundProvisionMode::RefreshStoredCapability,
        );
    }

    #[test]
    fn capability_expiring_now_is_disabled_for_android_provisioning() {
        let capability = ConnectionIntentCapability {
            revision: 7,
            expires_at: "1970-01-01T00:02:30Z".to_string(),
            connection_intent_recovery_v1: true,
        };

        let snapshot = android_background_capability_snapshot(Some(&capability), 150);

        assert_eq!(snapshot.revision, 7);
        assert!(!snapshot.enabled);
        assert_eq!(snapshot.expires_at, "1970-01-01T00:00:01Z");
    }

    #[test]
    fn malformed_capability_expiry_is_disabled_for_android_provisioning() {
        let capability = ConnectionIntentCapability {
            revision: 8,
            expires_at: "not-a-timestamp".to_string(),
            connection_intent_recovery_v1: true,
        };

        let snapshot = android_background_capability_snapshot(Some(&capability), 150);

        assert_eq!(snapshot.revision, 8);
        assert!(!snapshot.enabled);
        assert_eq!(snapshot.expires_at, "1970-01-01T00:00:01Z");
    }

    #[test]
    fn invalid_capability_revision_uses_the_disabled_android_sentinel() {
        let capability = ConnectionIntentCapability {
            revision: -1,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            connection_intent_recovery_v1: true,
        };

        let snapshot = android_background_capability_snapshot(Some(&capability), 150);

        assert_eq!(snapshot.revision, 0);
        assert!(!snapshot.enabled);
        assert_eq!(snapshot.expires_at, ANDROID_DISABLED_CAPABILITY_EXPIRES_AT);
    }

    #[tokio::test]
    async fn android_ui_start_waits_for_durable_service_ack_without_panel_start() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        assert!(android_start_epoch_is_current(7, 7));
        assert!(!android_start_epoch_is_current(7, 8));

        let service_calls = Arc::new(AtomicUsize::new(0));
        let panel_start_calls = Arc::new(AtomicUsize::new(0));
        let durable = Arc::new(AtomicBool::new(false));
        let request = tauri_plugin_tunnel_android::BeginConnectionIntentRequest {
            api_version: tauri_plugin_tunnel_android::TUNNEL_API_VERSION,
            template: tauri_plugin_tunnel_android::ConnectionIntentTemplateRequest {
                device_id: "11111111-1111-4111-8111-111111111111".to_string(),
                account_scope: "11111111-1111-4111-8111-111111111111".to_string(),
                layer: "stray".to_string(),
                tic_connection_mode: "dynamic".to_string(),
                route_mode: "standalone".to_string(),
                egress_mode: "ipv4".to_string(),
                allow_alternate: true,
                sync_binding_preferences: false,
                options: Default::default(),
            },
        };
        let calls = service_calls.clone();
        let acknowledged = durable.clone();
        let panel_calls = panel_start_calls.clone();

        let response = route_android_app_start(
            request,
            move |_| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                acknowledged.store(true, Ordering::SeqCst);
                Ok(
                    tauri_plugin_tunnel_android::ConnectionIntentStatusResponse {
                        generation: 1,
                        desired_active: true,
                        status: "recovering".to_string(),
                        lease_phase: Some("start_pending".to_string()),
                        next_retry_at_unix: None,
                        last_error_code: None,
                    },
                )
            },
            move || async move {
                panel_calls.fetch_add(1, Ordering::SeqCst);
                Err(CommandError::new("unexpected_panel_start", "unexpected"))
            },
        )
        .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => panic!("unexpected Android service rejection: {}", error.code()),
        };

        assert!(durable.load(Ordering::SeqCst));
        assert_eq!(service_calls.load(Ordering::SeqCst), 1);
        assert_eq!(panel_start_calls.load(Ordering::SeqCst), 0);
        assert_eq!(response.status, "recovering");
    }

    #[tokio::test]
    async fn android_new_ui_start_uses_legacy_contract_without_a_fresh_enabled_capability() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for capability in [
            None,
            Some(ConnectionIntentCapability {
                revision: 7,
                expires_at: "2099-01-01T00:00:00Z".to_string(),
                connection_intent_recovery_v1: false,
            }),
            Some(ConnectionIntentCapability {
                revision: 8,
                expires_at: "1970-01-01T00:01:40Z".to_string(),
                connection_intent_recovery_v1: true,
            }),
        ] {
            let service_calls = Arc::new(AtomicUsize::new(0));
            let legacy_calls = Arc::new(AtomicUsize::new(0));
            let recovery_request_calls = Arc::new(AtomicUsize::new(0));
            let service_observer = Arc::clone(&service_calls);
            let legacy_observer = Arc::clone(&legacy_calls);
            let recovery_request_observer = Arc::clone(&recovery_request_calls);

            let response = route_android_app_start_with_capability(
                &tauri_plugin_tunnel_android::ConnectionIntentStatusResponse::default(),
                capability.as_ref(),
                100,
                move || async move {
                    recovery_request_observer.fetch_add(1, Ordering::SeqCst);
                    Ok(android_begin_request())
                },
                move |_| async move {
                    service_observer.fetch_add(1, Ordering::SeqCst);
                    Err(CommandError::new("unexpected_service_begin", "unexpected"))
                },
                move || async move {
                    legacy_observer.fetch_add(1, Ordering::SeqCst);
                    Ok(test_connection("legacy-lease"))
                },
            )
            .await;
            let response = match response {
                Ok(response) => response,
                Err(error) => panic!("unexpected legacy route error: {}", error.code()),
            };

            assert_eq!(response.status, "connected");
            assert_eq!(
                response
                    .connection
                    .as_ref()
                    .map(|value| value.lease_id.as_str()),
                Some("legacy-lease")
            );
            assert_eq!(service_calls.load(Ordering::SeqCst), 0);
            assert_eq!(legacy_calls.load(Ordering::SeqCst), 1);
            assert_eq!(recovery_request_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn android_fresh_enabled_capability_selects_service_without_legacy_start() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let service_calls = Arc::new(AtomicUsize::new(0));
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let service_observer = Arc::clone(&service_calls);
        let legacy_observer = Arc::clone(&legacy_calls);
        let capability = ConnectionIntentCapability {
            revision: 9,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            connection_intent_recovery_v1: true,
        };

        let response = route_android_app_start_with_capability(
            &tauri_plugin_tunnel_android::ConnectionIntentStatusResponse::default(),
            Some(&capability),
            100,
            || async { Ok(android_begin_request()) },
            move |_| async move {
                service_observer.fetch_add(1, Ordering::SeqCst);
                Ok(durable_android_start_status())
            },
            move || async move {
                legacy_observer.fetch_add(1, Ordering::SeqCst);
                Ok(test_connection("unexpected-legacy-lease"))
            },
        )
        .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => panic!("unexpected recovery route error: {}", error.code()),
        };

        assert_eq!(response.status, "recovering");
        assert_eq!(service_calls.load(Ordering::SeqCst), 1);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn android_already_durable_operation_stays_service_owned_after_capability_disable() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let service_calls = Arc::new(AtomicUsize::new(0));
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let service_observer = Arc::clone(&service_calls);
        let legacy_observer = Arc::clone(&legacy_calls);
        let disabled = ConnectionIntentCapability {
            revision: 10,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            connection_intent_recovery_v1: false,
        };

        let response = route_android_app_start_with_capability(
            &durable_android_start_status(),
            Some(&disabled),
            100,
            || async { Ok(android_begin_request()) },
            move |_| async move {
                service_observer.fetch_add(1, Ordering::SeqCst);
                Ok(durable_android_start_status())
            },
            move || async move {
                legacy_observer.fetch_add(1, Ordering::SeqCst);
                Ok(test_connection("unexpected-legacy-lease"))
            },
        )
        .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => panic!("unexpected durable replay route error: {}", error.code()),
        };

        assert_eq!(response.status, "recovering");
        assert_eq!(service_calls.load(Ordering::SeqCst), 1);
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn android_selected_recovery_failure_never_falls_back_to_duplicate_legacy_start() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let legacy_observer = Arc::clone(&legacy_calls);
        let capability = ConnectionIntentCapability {
            revision: 11,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            connection_intent_recovery_v1: true,
        };

        let error = route_android_app_start_with_capability(
            &tauri_plugin_tunnel_android::ConnectionIntentStatusResponse::default(),
            Some(&capability),
            100,
            || async { Ok(android_begin_request()) },
            |_| async {
                Err(CommandError::new(
                    "background_transport_unavailable",
                    "temporarily unavailable",
                ))
            },
            move || async move {
                legacy_observer.fetch_add(1, Ordering::SeqCst);
                Ok(test_connection("unsafe-duplicate-legacy-lease"))
            },
        )
        .await;
        let error = match error {
            Ok(_) => panic!("a selected recovery path must return its own error"),
            Err(error) => error,
        };

        assert_eq!(error.code(), "background_transport_unavailable");
        assert_eq!(legacy_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn android_ui_start_accepts_every_valid_durable_service_phase_and_projection() {
        for (phase, status) in [
            ("start_pending", "recovering"),
            ("lease_acquired", "recovering"),
            ("cleanup_pending", "stopping"),
            ("stale_cleanup", "stopping"),
            ("active_checkpoint", "none"),
        ] {
            let response = route_android_app_start(
                android_begin_request(),
                move |_| async move {
                    Ok(
                        tauri_plugin_tunnel_android::ConnectionIntentStatusResponse {
                            generation: 9,
                            desired_active: true,
                            status: status.to_string(),
                            lease_phase: Some(phase.to_string()),
                            next_retry_at_unix: None,
                            last_error_code: None,
                        },
                    )
                },
                || async { Err(CommandError::new("unexpected_panel_start", "unexpected")) },
            )
            .await;
            assert!(response.is_ok(), "phase={phase} status={status}");
        }
    }

    #[tokio::test]
    async fn android_ui_start_rejects_idle_or_inconsistent_service_acknowledgement() {
        for (desired_active, phase, status) in [
            (true, None, "none"),
            (false, Some("start_pending"), "recovering"),
            (true, Some("lease_acquired"), "none"),
            (true, Some("cleanup_pending"), "recovering"),
            (true, Some("active_checkpoint"), "blocked_terminal"),
            (true, Some("invalid"), "recovering"),
        ] {
            let response = route_android_app_start(
                android_begin_request(),
                move |_| async move {
                    Ok(
                        tauri_plugin_tunnel_android::ConnectionIntentStatusResponse {
                            generation: 9,
                            desired_active,
                            status: status.to_string(),
                            lease_phase: phase.map(str::to_string),
                            next_retry_at_unix: None,
                            last_error_code: None,
                        },
                    )
                },
                || async { Err(CommandError::new("unexpected_panel_start", "unexpected")) },
            )
            .await;
            assert!(response.is_err(), "phase={phase:?} status={status}");
        }
    }

    #[test]
    fn android_service_start_invalidates_a_stopped_projection_before_acknowledgement() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(false);
        let ticket = coordinator.start_ticket();

        let projection_ticket = match coordinator.begin_projected_start(ticket, &projection) {
            Ok(projection_ticket) => projection_ticket,
            Err(error) => panic!("unexpected projected start failure: {}", error.code()),
        };

        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::Recovering,
        );
        if let Err(error) =
            coordinator.commit_projected_start(ticket, projection_ticket, &projection, true)
        {
            panic!(
                "unexpected projected start commit failure: {}",
                error.code()
            );
        }
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::Recovering,
        );
    }

    #[tokio::test]
    async fn late_android_start_acknowledgement_cannot_override_a_completed_stop() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(false);
        let ticket = coordinator.start_ticket();
        let projection_ticket = match coordinator.begin_projected_start(ticket, &projection) {
            Ok(projection_ticket) => projection_ticket,
            Err(error) => panic!("unexpected projected start failure: {}", error.code()),
        };

        let stop_ticket = coordinator.begin_projected_stop();
        assert!(coordinator.commit_projected_action(stop_ticket, &projection, false));

        let error = coordinator
            .commit_projected_start(ticket, projection_ticket, &projection, true)
            .expect_err("a cancelled start must not publish its late acknowledgement");
        assert_eq!(error.code(), "connection_intent_cancelled");
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::None,
        );
    }

    #[test]
    fn stale_android_status_cannot_override_a_completed_stop() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(true);
        let stale_status_ticket = coordinator.projection_ticket();

        let stop_ticket = coordinator.begin_projected_stop();
        assert!(coordinator.commit_projected_action(stop_ticket, &projection, false));
        assert!(!coordinator.observe_projected_status(stale_status_ticket, &projection, true,));
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::None,
        );
    }

    #[test]
    fn older_android_status_poll_cannot_override_a_newer_completed_poll() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(true);
        let older_status_ticket = coordinator.projection_ticket();
        let newer_status_ticket = coordinator.projection_ticket();

        assert!(coordinator.observe_projected_status(newer_status_ticket, &projection, false,));
        assert!(!coordinator.observe_projected_status(older_status_ticket, &projection, true,));
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::None,
        );
    }

    #[test]
    fn late_android_stop_acknowledgement_cannot_override_a_new_start() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(true);
        let stop_ticket = coordinator.begin_projected_stop();
        let start_ticket = coordinator.start_ticket();
        let projected_start = match coordinator.begin_projected_start(start_ticket, &projection) {
            Ok(projected_start) => projected_start,
            Err(error) => panic!("unexpected projected start failure: {}", error.code()),
        };

        assert!(coordinator.commit_projected_action(projected_start, &projection, true));
        assert!(!coordinator.commit_projected_action(stop_ticket, &projection, false));
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::Recovering,
        );
    }

    #[test]
    fn android_status_cannot_restore_stopped_while_start_is_pending() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(false);
        let start_ticket = coordinator.start_ticket();
        let projected_start = match coordinator.begin_projected_start(start_ticket, &projection) {
            Ok(projected_start) => projected_start,
            Err(error) => panic!("unexpected projected start failure: {}", error.code()),
        };
        let status_ticket = coordinator.projection_ticket();

        assert!(!coordinator.observe_projected_status(status_ticket, &projection, false));
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::Recovering,
        );
        assert!(coordinator.commit_projected_action(projected_start, &projection, true));
    }

    #[test]
    fn android_quick_snapshot_invalidates_an_older_status_poll() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(true);
        let stale_status_ticket = coordinator.projection_ticket();
        let quick_snapshot_ticket = coordinator.projection_ticket();

        assert!(coordinator.observe_projected_snapshot(
            quick_snapshot_ticket,
            &projection,
            true,
            Some(false),
        ));

        assert!(!coordinator.observe_projected_status(stale_status_ticket, &projection, true,));
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::None,
        );
    }

    #[test]
    fn stale_android_quick_snapshot_cannot_override_a_completed_stop() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(true);
        let stale_snapshot_ticket = coordinator.projection_ticket();
        let stop_ticket = coordinator.begin_projected_stop();
        assert!(coordinator.commit_projected_action(stop_ticket, &projection, false));

        assert!(!coordinator.observe_projected_snapshot(
            stale_snapshot_ticket,
            &projection,
            true,
            Some(true),
        ));
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::None,
        );
    }

    #[test]
    fn android_quick_snapshot_cannot_override_a_pending_start() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(false);
        let start_ticket = coordinator.start_ticket();
        let projected_start = match coordinator.begin_projected_start(start_ticket, &projection) {
            Ok(projected_start) => projected_start,
            Err(error) => panic!("unexpected projected start failure: {}", error.code()),
        };
        let quick_snapshot_ticket = coordinator.projection_ticket();

        assert!(!coordinator.observe_projected_snapshot(
            quick_snapshot_ticket,
            &projection,
            true,
            Some(false),
        ));
        assert!(coordinator.commit_projected_action(projected_start, &projection, true));
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::Recovering,
        );
    }

    #[test]
    fn newer_android_quick_snapshot_supersedes_an_older_completed_snapshot() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(true);
        let older_snapshot_ticket = coordinator.projection_ticket();
        let newer_snapshot_ticket = coordinator.projection_ticket();

        assert!(coordinator.observe_projected_snapshot(
            older_snapshot_ticket,
            &projection,
            true,
            Some(true),
        ));
        assert!(coordinator.observe_projected_snapshot(
            newer_snapshot_ticket,
            &projection,
            true,
            Some(false),
        ));
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::None,
        );
    }

    #[test]
    fn android_status_failure_uses_projection_after_a_concurrent_start() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(false);
        let stale_status_ticket = coordinator.projection_ticket();
        let start_ticket = coordinator.start_ticket();
        if let Err(error) = coordinator.begin_projected_start(start_ticket, &projection) {
            panic!("unexpected projected start failure: {}", error.code());
        }

        assert_eq!(
            coordinator.projected_status_fallback(stale_status_ticket, &projection),
            nelomai_client_core::ConnectionIntentStatus::Recovering,
        );
    }

    #[test]
    fn android_status_finalization_discards_a_reply_that_precedes_start() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(false);
        let status_ticket = coordinator.projection_ticket();
        let start_ticket = coordinator.start_ticket();
        if let Err(error) = coordinator.begin_projected_start(start_ticket, &projection) {
            panic!("unexpected projected start failure: {}", error.code());
        }

        let (status_is_current, fallback) =
            coordinator.finalize_projected_status(status_ticket, &projection, Some(false));
        assert!(!status_is_current);
        assert_eq!(
            project_android_connection_intent_status(
                status_is_current.then_some(("none", None)),
                fallback,
            ),
            (
                nelomai_client_core::ConnectionIntentStatus::Recovering,
                None,
            ),
        );
    }

    #[test]
    fn late_android_clear_cannot_override_a_new_start() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(true);
        let clear_ticket = coordinator.begin_projected_clear();
        let start_ticket = coordinator.start_ticket();
        let projected_start = match coordinator.begin_projected_start(start_ticket, &projection) {
            Ok(projected_start) => projected_start,
            Err(error) => panic!("unexpected projected start failure: {}", error.code()),
        };

        assert!(coordinator.commit_projected_action(projected_start, &projection, true));
        assert!(!coordinator.commit_projected_action(clear_ticket, &projection, false));
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::Recovering,
        );
    }

    #[test]
    fn android_projected_mutations_dispatch_in_ticket_order() {
        use std::sync::{mpsc, Arc, Mutex};
        use std::time::Duration;

        let coordinator = Arc::new(AndroidUiStartStopCoordinator::new());
        let projection = Arc::new(AndroidDesiredActiveProjection::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let (clear_entered_tx, clear_entered_rx) = mpsc::channel();
        let (release_clear_tx, release_clear_rx) = mpsc::channel();
        let clear_coordinator = Arc::clone(&coordinator);
        let clear_events = Arc::clone(&events);
        let clear = std::thread::spawn(move || {
            clear_coordinator.dispatch_projected_clear(|| {
                clear_entered_tx.send(()).unwrap();
                release_clear_rx.recv().unwrap();
                clear_events.lock().unwrap().push("clear");
                Ok::<_, CommandError>(())
            })
        });
        clear_entered_rx.recv().unwrap();

        let (toggle_entered_tx, toggle_entered_rx) = mpsc::channel();
        let toggle_coordinator = Arc::clone(&coordinator);
        let toggle_projection = Arc::clone(&projection);
        let toggle_events = Arc::clone(&events);
        let toggle = std::thread::spawn(move || {
            toggle_coordinator.dispatch_projected_toggle(&toggle_projection, || {
                toggle_entered_tx.send(()).unwrap();
                toggle_events.lock().unwrap().push("toggle");
                Ok::<_, CommandError>(())
            })
        });

        assert!(
            toggle_entered_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "a newer mutation must not dispatch before the ticket-owning clear",
        );
        release_clear_tx.send(()).unwrap();
        let (_, clear_result) = clear.join().unwrap();
        let (_, toggle_result) = toggle.join().unwrap();
        assert!(clear_result.is_ok());
        assert!(toggle_result.is_ok());
        assert_eq!(events.lock().unwrap().as_slice(), &["clear", "toggle"]);
    }

    #[tokio::test]
    async fn android_start_and_stop_dispatch_in_ticket_order() {
        use std::sync::{Arc, Mutex};

        let coordinator = Arc::new(AndroidUiStartStopCoordinator::new());
        let projection = Arc::new(AndroidDesiredActiveProjection::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let (start_entered_tx, start_entered_rx) = tokio::sync::oneshot::channel();
        let (release_start_tx, release_start_rx) = tokio::sync::oneshot::channel();
        let start_ticket = coordinator.start_ticket();
        let start_coordinator = Arc::clone(&coordinator);
        let start_projection = Arc::clone(&projection);
        let start_events = Arc::clone(&events);
        let start = tokio::spawn(async move {
            start_coordinator
                .run_projected_start_side_effect(start_ticket, &start_projection, async move {
                    start_events.lock().unwrap().push("start");
                    let _ = start_entered_tx.send(());
                    let _ = release_start_rx.await;
                    Ok(())
                })
                .await
        });
        start_entered_rx.await.unwrap();

        let stop_events = Arc::clone(&events);
        let (stop_projection_ticket, stop_result) =
            coordinator.dispatch_projected_stop(move || {
                stop_events.lock().unwrap().push("stop");
                Ok::<_, CommandError>(())
            });
        assert!(stop_result.is_ok());
        let _ = release_start_tx.send(());
        let (projected_start_ticket, ()) = match start.await.unwrap() {
            Ok(result) => result,
            Err(error) => panic!("unexpected projected Start failure: {}", error.code()),
        };

        assert!(coordinator.commit_projected_action(stop_projection_ticket, &projection, false,));
        let error = coordinator
            .commit_projected_start(start_ticket, projected_start_ticket, &projection, true)
            .expect_err("Stop must invalidate a Start dispatched immediately before it");
        assert_eq!(error.code(), "connection_intent_cancelled");
        assert_eq!(events.lock().unwrap().as_slice(), &["start", "stop"]);
    }

    #[test]
    fn android_toggle_and_clear_fence_contradictory_status_polls() {
        let coordinator = AndroidUiStartStopCoordinator::new();
        let projection = AndroidDesiredActiveProjection::new();
        projection.observe_confirmed(false);
        let toggle_ticket = coordinator.begin_projected_toggle(&projection);
        let toggle_status_ticket = coordinator.projection_ticket();

        assert!(!coordinator.observe_projected_status(toggle_status_ticket, &projection, false,));
        coordinator.finish_projected_action(toggle_ticket);
        let recovered_status_ticket = coordinator.projection_ticket();
        assert!(coordinator.observe_projected_status(recovered_status_ticket, &projection, true,));

        let stale_status_ticket = coordinator.projection_ticket();
        let clear_ticket = coordinator.begin_projected_clear();
        assert!(coordinator.commit_projected_action(clear_ticket, &projection, false));
        assert!(!coordinator.observe_projected_status(stale_status_ticket, &projection, true,));
        assert_eq!(
            projection.status_unavailable_fallback(),
            nelomai_client_core::ConnectionIntentStatus::None,
        );
    }

    #[tokio::test]
    async fn android_stop_invalidates_a_blocked_start_before_its_late_ack() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let coordinator = Arc::new(AndroidUiStartStopCoordinator::new());
        let begin_calls = Arc::new(AtomicUsize::new(0));
        let (begin_entered_tx, begin_entered_rx) = tokio::sync::oneshot::channel();
        let (release_begin_tx, release_begin_rx) = tokio::sync::oneshot::channel();
        let first_ticket = coordinator.start_ticket();
        let first_coordinator = Arc::clone(&coordinator);
        let first_side_effect_coordinator = Arc::clone(&coordinator);
        let first_begin_calls = Arc::clone(&begin_calls);
        let first = tokio::spawn(async move {
            first_coordinator
                .run_start(first_ticket, || async move {
                    first_side_effect_coordinator
                        .run_start_side_effect(first_ticket, async move {
                            route_android_app_start(
                                android_begin_request(),
                                move |_| async move {
                                    first_begin_calls.fetch_add(1, Ordering::SeqCst);
                                    let _ = begin_entered_tx.send(());
                                    let _ = release_begin_rx.await;
                                    Ok(
                                        tauri_plugin_tunnel_android::ConnectionIntentStatusResponse {
                                            generation: 1,
                                            desired_active: true,
                                            status: "recovering".to_string(),
                                            lease_phase: Some("start_pending".to_string()),
                                            next_retry_at_unix: None,
                                            last_error_code: None,
                                        },
                                    )
                                },
                                || async {
                                    Err(CommandError::new("unexpected_panel_start", "unexpected"))
                                },
                            )
                            .await
                        })
                        .await
                })
                .await
        });
        begin_entered_rx.await.unwrap();

        let second_ticket = coordinator.start_ticket();
        let second_coordinator = Arc::clone(&coordinator);
        let second_side_effect_coordinator = Arc::clone(&coordinator);
        let second_begin_calls = Arc::clone(&begin_calls);
        let (second_waiting_tx, second_waiting_rx) = tokio::sync::oneshot::channel();
        let second = tokio::spawn(async move {
            let _ = second_waiting_tx.send(());
            second_coordinator
                .run_start(second_ticket, || async move {
                    second_side_effect_coordinator
                        .run_start_side_effect(second_ticket, async move {
                            route_android_app_start(
                                android_begin_request(),
                                move |_| async move {
                                    second_begin_calls.fetch_add(1, Ordering::SeqCst);
                                    Ok(
                                        tauri_plugin_tunnel_android::ConnectionIntentStatusResponse {
                                            generation: 2,
                                            desired_active: true,
                                            status: "recovering".to_string(),
                                            lease_phase: Some("start_pending".to_string()),
                                            next_retry_at_unix: None,
                                            last_error_code: None,
                                        },
                                    )
                                },
                                || async {
                                    Err(CommandError::new("unexpected_panel_start", "unexpected"))
                                },
                            )
                            .await
                        })
                        .await
                })
                .await
        });
        second_waiting_rx.await.unwrap();

        let (cancel_dispatched_tx, cancel_dispatched_rx) = tokio::sync::oneshot::channel();
        let stop_coordinator = Arc::clone(&coordinator);
        let cancellation_observer = Arc::clone(&coordinator);
        let observed_start_ticket = coordinator.start_ticket();
        let stop = tokio::spawn(async move {
            stop_coordinator
                .run_stop(|| async move {
                    route_android_connection_stop(|| async move {
                        let invalidated = cancellation_observer
                            .ensure_current(observed_start_ticket)
                            .expect_err("Stop must invalidate its epoch before service dispatch");
                        assert_eq!(invalidated.code(), "connection_intent_cancelled");
                        let _ = cancel_dispatched_tx.send(());
                        Ok(
                            tauri_plugin_tunnel_android::ConnectionIntentStatusResponse {
                                generation: 2,
                                desired_active: false,
                                status: "stopping".to_string(),
                                lease_phase: Some("start_pending".to_string()),
                                next_retry_at_unix: None,
                                last_error_code: None,
                            },
                        )
                    })
                    .await
                })
                .await
        });

        tokio::time::timeout(Duration::from_secs(1), cancel_dispatched_rx)
            .await
            .expect("Stop must dispatch cancellation without waiting for the occupied start gate")
            .unwrap();
        let stopped = tokio::time::timeout(Duration::from_secs(1), stop)
            .await
            .expect("Stop must complete before the blocked begin acknowledgement is released")
            .unwrap();
        assert!(stopped.is_ok());
        let _ = release_begin_tx.send(());

        for result in [first.await.unwrap(), second.await.unwrap()] {
            let error = match result {
                Ok(_) => panic!("a Stop-invalidated start must not project recovering"),
                Err(error) => error,
            };
            assert_eq!(error.code(), "connection_intent_cancelled");
        }
        assert_eq!(begin_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn android_stop_before_true_side_effect_prevents_recovery_and_legacy_dispatch() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for branch in ["recovery", "legacy"] {
            let coordinator = Arc::new(AndroidUiStartStopCoordinator::new());
            let side_effects = Arc::new(AtomicUsize::new(0));
            let (preflight_entered_tx, preflight_entered_rx) = tokio::sync::oneshot::channel();
            let (release_preflight_tx, release_preflight_rx) = tokio::sync::oneshot::channel();
            let ticket = coordinator.start_ticket();
            let start_coordinator = Arc::clone(&coordinator);
            let side_effect_coordinator = Arc::clone(&coordinator);
            let side_effect_observer = Arc::clone(&side_effects);
            let start = tokio::spawn(async move {
                start_coordinator
                    .run_start(ticket, || async move {
                        let _ = preflight_entered_tx.send(());
                        let _ = release_preflight_rx.await;
                        side_effect_coordinator
                            .run_start_side_effect(ticket, async move {
                                side_effect_observer.fetch_add(1, Ordering::SeqCst);
                                Ok(branch)
                            })
                            .await
                    })
                    .await
            });
            preflight_entered_rx.await.unwrap();

            if let Err(error) = coordinator.run_stop(|| async { Ok(()) }).await {
                panic!("unexpected Stop failure: {}", error.code());
            }
            let _ = release_preflight_tx.send(());

            let error = start
                .await
                .unwrap()
                .expect_err("Stop completed before dispatch must own both start branches");
            assert_eq!(error.code(), "connection_intent_cancelled");
            assert_eq!(
                side_effects.load(Ordering::SeqCst),
                0,
                "stale {branch} side effect dispatched after Stop",
            );
        }
    }

    #[tokio::test]
    async fn android_ui_starts_remain_serialized() {
        let coordinator = Arc::new(AndroidUiStartStopCoordinator::new());
        let (first_entered_tx, first_entered_rx) = tokio::sync::oneshot::channel();
        let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel();
        let first_ticket = coordinator.start_ticket();
        let first_coordinator = Arc::clone(&coordinator);
        let first = tokio::spawn(async move {
            first_coordinator
                .run_start(first_ticket, || async move {
                    let _ = first_entered_tx.send(());
                    let _ = release_first_rx.await;
                    Ok(1)
                })
                .await
        });
        first_entered_rx.await.unwrap();

        let (second_entered_tx, mut second_entered_rx) = tokio::sync::oneshot::channel();
        let second_ticket = coordinator.start_ticket();
        let second_coordinator = Arc::clone(&coordinator);
        let second = tokio::spawn(async move {
            second_coordinator
                .run_start(second_ticket, || async move {
                    let _ = second_entered_tx.send(());
                    Ok(2)
                })
                .await
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut second_entered_rx)
                .await
                .is_err(),
            "a second Start must wait for the first Start acknowledgement",
        );
        let _ = release_first_tx.send(());

        match first.await.unwrap() {
            Ok(value) => assert_eq!(value, 1),
            Err(error) => panic!("unexpected first Start error: {}", error.code()),
        }
        tokio::time::timeout(Duration::from_secs(1), &mut second_entered_rx)
            .await
            .expect("the second Start must run after the first acknowledgement")
            .unwrap();
        match second.await.unwrap() {
            Ok(value) => assert_eq!(value, 2),
            Err(error) => panic!("unexpected second Start error: {}", error.code()),
        }
    }

    #[tokio::test]
    async fn android_logout_bypasses_busy_native_provision_and_preserves_owner_failure() {
        let _busy = ANDROID_BACKGROUND_PROVISION_GATE.lock().await;
        let entered = std::sync::atomic::AtomicBool::new(false);
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            route_android_logout(async {
                entered.store(true, std::sync::atomic::Ordering::SeqCst);
                Err::<(), _>(CommandError::new(
                    "physical_stop_failed",
                    "synthetic failure",
                ))
            }),
        )
        .await
        .expect("owner cancellation must not wait for native provision");
        assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(result.unwrap_err().code(), "physical_stop_failed");
    }
    fn android_begin_request() -> tauri_plugin_tunnel_android::BeginConnectionIntentRequest {
        tauri_plugin_tunnel_android::BeginConnectionIntentRequest {
            api_version: tauri_plugin_tunnel_android::TUNNEL_API_VERSION,
            template: tauri_plugin_tunnel_android::ConnectionIntentTemplateRequest {
                device_id: "11111111-1111-4111-8111-111111111111".to_string(),
                account_scope: "11111111-1111-4111-8111-111111111111".to_string(),
                layer: "stray".to_string(),
                tic_connection_mode: "dynamic".to_string(),
                route_mode: "standalone".to_string(),
                egress_mode: "ipv4".to_string(),
                allow_alternate: true,
                sync_binding_preferences: false,
                options: Default::default(),
            },
        }
    }

    fn durable_android_start_status() -> tauri_plugin_tunnel_android::ConnectionIntentStatusResponse
    {
        tauri_plugin_tunnel_android::ConnectionIntentStatusResponse {
            generation: 1,
            desired_active: true,
            status: "recovering".to_string(),
            lease_phase: Some("start_pending".to_string()),
            next_retry_at_unix: None,
            last_error_code: None,
        }
    }

    fn test_connection(lease_id: &str) -> Connection {
        Connection {
            lease_id: lease_id.to_string(),
            pool_id: None,
            layer: Layer::Stray,
            transport_protocol: Default::default(),
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            egress_mode: EgressMode::Ipv4,
            probe_url: None,
            status: LeaseStatus::Issued,
            pinned: false,
            stopped_at: None,
        }
    }

    #[tokio::test]
    async fn android_quick_toggle_routes_only_to_service_without_rust_bootstrap_or_start() {
        use std::sync::{Arc, Mutex};

        let events = Arc::new(Mutex::new(Vec::new()));
        let service_events = events.clone();
        let bootstrap_events = events.clone();
        let start_events = events.clone();

        let status = route_android_quick_toggle(
            move || async move {
                service_events.lock().unwrap().push("service");
                Ok(
                    tauri_plugin_tunnel_android::ConnectionIntentStatusResponse {
                        generation: 7,
                        desired_active: true,
                        status: "recovering".to_string(),
                        lease_phase: Some("start_pending".to_string()),
                        next_retry_at_unix: None,
                        last_error_code: None,
                    },
                )
            },
            move || async move {
                bootstrap_events.lock().unwrap().push("rust_bootstrap");
                Ok(())
            },
            move || async move {
                start_events.lock().unwrap().push("rust_start");
                Ok(())
            },
        )
        .await;
        let status = match status {
            Ok(status) => status,
            Err(error) => panic!("unexpected route failure: {}", error.code()),
        };

        assert_eq!(status.generation, 7);
        assert_eq!(*events.lock().unwrap(), vec!["service"]);
    }

    #[tokio::test]
    async fn android_stop_routes_directly_to_atomic_service_cancel() {
        use std::sync::Mutex;

        let calls = Arc::new(Mutex::new(Vec::new()));
        let service_observed = Arc::clone(&calls);
        let legacy_observed = Arc::clone(&calls);

        let status = route_android_connection_stop_with_legacy(
            {
                let calls = Arc::clone(&calls);
                move || calls.lock().unwrap().push("cancel_pending_legacy_start")
            },
            move || async move {
                service_observed.lock().unwrap().push("cancel_current");
                Ok(
                    tauri_plugin_tunnel_android::ConnectionIntentStatusResponse {
                        generation: 42,
                        desired_active: false,
                        status: "stopping".to_string(),
                        lease_phase: Some("cleanup_pending".to_string()),
                        next_retry_at_unix: None,
                        last_error_code: None,
                    },
                )
            },
            move || async move {
                legacy_observed
                    .lock()
                    .unwrap()
                    .push("unexpected_legacy_stop");
                Ok(())
            },
        )
        .await;
        let status = match status {
            Ok(status) => status,
            Err(error) => panic!("unexpected route failure: {}", error.code()),
        };

        assert_eq!(status.generation, 42);
        assert_eq!(
            *calls.lock().unwrap(),
            vec!["cancel_pending_legacy_start", "cancel_current"]
        );
    }

    #[tokio::test]
    async fn android_service_owned_stop_cancels_an_already_dispatched_legacy_start() {
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

        let coordinator = Arc::new(AndroidUiStartStopCoordinator::new());
        let ui_start_ticket = coordinator.start_ticket();
        let legacy_cancel_epoch = Arc::new(AtomicU64::new(0));
        let captured_legacy_epoch = legacy_cancel_epoch.load(Ordering::SeqCst);
        let legacy_start_side_effects = Arc::new(AtomicUsize::new(0));
        let legacy_stops = Arc::new(AtomicUsize::new(0));
        let (legacy_entered_tx, legacy_entered_rx) = tokio::sync::oneshot::channel();
        let (release_legacy_tx, release_legacy_rx) = tokio::sync::oneshot::channel();
        let late_epoch = Arc::clone(&legacy_cancel_epoch);
        let late_side_effects = Arc::clone(&legacy_start_side_effects);
        let legacy_start = tokio::spawn(async move {
            let _ = legacy_entered_tx.send(());
            let _ = release_legacy_rx.await;
            if late_epoch.load(Ordering::SeqCst) != captured_legacy_epoch {
                return Err(CommandError::new(
                    "connection_intent_cancelled",
                    "Подключение отменено",
                ));
            }
            late_side_effects.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        legacy_entered_rx.await.unwrap();

        let stop_coordinator = Arc::clone(&coordinator);
        let cancellation_observer = Arc::clone(&coordinator);
        let stop_epoch = Arc::clone(&legacy_cancel_epoch);
        let stop_calls = Arc::clone(&legacy_stops);
        let stopped = stop_coordinator
            .run_stop(|| async move {
                route_android_connection_stop_with_legacy(
                    move || {
                        let invalidated = cancellation_observer
                            .ensure_current(ui_start_ticket)
                            .expect_err("UI epoch must be invalidated before core cancellation");
                        assert_eq!(invalidated.code(), "connection_intent_cancelled");
                        stop_epoch.fetch_add(1, Ordering::SeqCst);
                    },
                    || async {
                        Ok(
                            tauri_plugin_tunnel_android::ConnectionIntentStatusResponse {
                                generation: 9,
                                desired_active: false,
                                status: "stopping".to_string(),
                                lease_phase: Some("cleanup_pending".to_string()),
                                next_retry_at_unix: None,
                                last_error_code: None,
                            },
                        )
                    },
                    move || async move {
                        stop_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .await
            })
            .await;
        assert!(stopped.is_ok());
        assert_eq!(legacy_stops.load(Ordering::SeqCst), 0);

        let _ = release_legacy_tx.send(());
        let error = legacy_start
            .await
            .unwrap()
            .expect_err("a completed mixed-control Stop must invalidate the legacy start epoch");
        assert_eq!(error.code(), "connection_intent_cancelled");
        assert_eq!(legacy_start_side_effects.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn android_stop_cancels_service_before_stopping_a_legacy_connection() {
        use std::sync::Mutex;

        let events = Arc::new(Mutex::new(Vec::new()));
        let service_events = Arc::clone(&events);
        let legacy_events = Arc::clone(&events);

        let status = route_android_connection_stop_with_legacy(
            {
                let events = Arc::clone(&events);
                move || events.lock().unwrap().push("cancel_pending_legacy_start")
            },
            move || async move {
                service_events.lock().unwrap().push("cancel_current");
                Ok(
                    tauri_plugin_tunnel_android::ConnectionIntentStatusResponse {
                        generation: 7,
                        desired_active: false,
                        status: "none".to_string(),
                        lease_phase: None,
                        next_retry_at_unix: None,
                        last_error_code: None,
                    },
                )
            },
            move || async move {
                legacy_events.lock().unwrap().push("legacy_stop");
                Ok(())
            },
        )
        .await;
        let status = match status {
            Ok(status) => status,
            Err(error) => panic!("unexpected legacy stop route error: {}", error.code()),
        };

        assert_eq!(status.generation, 7);
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "cancel_pending_legacy_start",
                "cancel_current",
                "legacy_stop"
            ]
        );
    }
}
