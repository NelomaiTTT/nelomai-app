use crate::{
    commands::{CommandError, StartCommandResponse},
    diagnostics::{
        AppDiagnostics, ConnectionIntentDiagnosticActions, ConnectionIntentDiagnosticEvent,
        ConnectionIntentDiagnosticsEpisode, ConnectionIntentReasonClass,
        ConnectionIntentReportTrigger,
    },
    preferences::{connection_egress_mode, AppPreferenceStore},
    NativeApplication,
};
use nelomai_client_application::ApplicationError;
#[cfg(any(target_os = "macos", test))]
use nelomai_client_core::StallRecoveryPlan;
use nelomai_client_core::{
    classify_recovery, ConnectOptions, ConnectionIntentCoordinator, ConnectionIntentStatus,
    CoreApiError, CoreError, CoreState, IntentGeneration, Phase, RecoveryDecision,
    RecoveryPolicyContext, StartDisposition,
};
#[cfg(target_os = "macos")]
use nelomai_client_core::{
    RecoveryTransport, StallTrigger, StalledDataPlaneRecovery, StalledDataPlaneRecoveryOutcome,
};
use nelomai_contracts::{
    allows_new_connection_intent_operation, BindPeerRequest, Connection,
    ConnectionIntentCapability, LeaseStatus,
};
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;
use tokio::sync::{Mutex, Notify};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConnectionIntentSnapshot {
    pub status: ConnectionIntentStatus,
    pub next_retry_at_unix: Option<i64>,
}

impl Default for ConnectionIntentSnapshot {
    fn default() -> Self {
        Self {
            status: ConnectionIntentStatus::None,
            next_retry_at_unix: None,
        }
    }
}

struct RuntimeState {
    coordinator: ConnectionIntentCoordinator,
    options: Option<ConnectOptions>,
    policy: RecoveryPolicyContext,
    next_retry_at_unix: Option<i64>,
    retry_not_before_unix: Option<i64>,
    reconcile_before_attempt: bool,
    repair_before_attempt: bool,
    refresh_capability_before_attempt: bool,
    armed: bool,
    diagnostics_episode: ConnectionIntentDiagnosticsEpisode,
    attempt_kind: AttemptKind,
    retry_count: u32,
    owned_lease_id: Option<String>,
    initial_preflight: Option<InitialDesktopPreflight>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InitialDesktopPreflight {
    expected_device_id: Option<String>,
    binding_request: Option<BindPeerRequest>,
    quick_toggle_skip_probe_refresh: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitialDesktopStartMode {
    Recovery,
    Legacy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InitialDesktopPreflightAction {
    ContinueRecovery,
    RetryIntent,
    RunLegacy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum AttemptKind {
    #[default]
    Start,
    StallReplacement,
}

#[derive(Debug, Eq, PartialEq)]
enum StartRuntimeAction {
    Run(IntentGeneration),
    Wait(Option<i64>),
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            coordinator: ConnectionIntentCoordinator::default(),
            options: None,
            policy: RecoveryPolicyContext::default(),
            next_retry_at_unix: None,
            retry_not_before_unix: None,
            reconcile_before_attempt: false,
            repair_before_attempt: false,
            refresh_capability_before_attempt: false,
            armed: false,
            diagnostics_episode: ConnectionIntentDiagnosticsEpisode::default(),
            attempt_kind: AttemptKind::Start,
            retry_count: 0,
            owned_lease_id: None,
            initial_preflight: None,
        }
    }
}

pub(crate) struct DesktopConnectionIntent {
    app: AppHandle,
    application: Arc<NativeApplication>,
    diagnostics: Arc<AppDiagnostics>,
    state: Mutex<RuntimeState>,
    wake: Notify,
    notifier: Arc<dyn SlowRecoveryNotifier>,
}

trait SlowRecoveryNotifier: Send + Sync {
    fn show(&self, title: &str, body: &str) -> Result<(), String>;
}

fn show_slow_recovery_notification(notifier: &dyn SlowRecoveryNotifier) -> Result<(), String> {
    notifier.show(
        "Проверяем подключение",
        "Приложение проверяет стабильность подключения и при необходимости повторит попытку автоматически.",
    )
}

struct SystemSlowRecoveryNotifier {
    app: AppHandle,
}

impl SlowRecoveryNotifier for SystemSlowRecoveryNotifier {
    fn show(&self, title: &str, body: &str) -> Result<(), String> {
        self.app
            .notification()
            .builder()
            .title(title)
            .body(body)
            .show()
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeConnectionChangedEvent {
    error: Option<CommandError>,
    action: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeConnectionIntentNotificationEvent {
    kind: &'static str,
    title: &'static str,
    body: &'static str,
}

impl DesktopConnectionIntent {
    pub(crate) fn new(
        app: AppHandle,
        application: Arc<NativeApplication>,
        diagnostics: Arc<AppDiagnostics>,
    ) -> Self {
        let notifier = Arc::new(SystemSlowRecoveryNotifier { app: app.clone() });
        Self {
            app,
            application,
            diagnostics,
            state: Mutex::new(RuntimeState::default()),
            wake: Notify::new(),
            notifier,
        }
    }

    pub(crate) fn spawn(self: &Arc<Self>) {
        let runtime = self.clone();
        tauri::async_runtime::spawn(async move {
            runtime.scheduler_loop().await;
        });
    }

    pub(crate) async fn snapshot(&self) -> ConnectionIntentSnapshot {
        let state = self.state.lock().await;
        ConnectionIntentSnapshot {
            status: state.coordinator.status(),
            next_retry_at_unix: state.next_retry_at_unix,
        }
    }

    pub(crate) async fn start_or_resume_with_initial_preflight(
        &self,
        options: ConnectOptions,
        expected_device_id: String,
        binding_request: Option<BindPeerRequest>,
        now_unix: i64,
    ) -> Result<StartCommandResponse, CommandError> {
        self.start_or_resume_internal(
            options,
            now_unix,
            Some(InitialDesktopPreflight {
                expected_device_id: Some(expected_device_id),
                binding_request,
                quick_toggle_skip_probe_refresh: None,
            }),
        )
        .await
    }

    pub(crate) async fn start_or_resume_quick_toggle(
        &self,
        skip_probe_refresh: bool,
        now_unix: i64,
    ) -> Result<StartCommandResponse, CommandError> {
        self.start_or_resume_internal(
            quick_toggle_placeholder_options(),
            now_unix,
            Some(InitialDesktopPreflight {
                expected_device_id: None,
                binding_request: None,
                quick_toggle_skip_probe_refresh: Some(skip_probe_refresh),
            }),
        )
        .await
    }

    async fn start_or_resume_internal(
        &self,
        options: ConnectOptions,
        now_unix: i64,
        initial_preflight: Option<InitialDesktopPreflight>,
    ) -> Result<StartCommandResponse, CommandError> {
        let core_state = self.application.state().await;
        let action = {
            let mut state = self.state.lock().await;
            let previous_generation = state.coordinator.generation();
            let disposition = state
                .coordinator
                .start_or_resume(options.clone(), now_unix)
                .map_err(|error| CommandError::new("connection_busy", error.to_string()))?;
            match disposition {
                StartDisposition::Connected(connection) => {
                    if connection_matches_core_state(&core_state, &connection) {
                        return Ok(StartCommandResponse::connected(connection));
                    }
                    if !state.coordinator.cancel_intent(previous_generation) {
                        return Err(CommandError::new(
                            "connection_busy",
                            "Предыдущее подключение ещё завершается",
                        ));
                    }
                    state.armed = false;
                    state.owned_lease_id = None;
                    state.attempt_kind = AttemptKind::Start;
                    let StartDisposition::Recovering { generation, .. } = state
                        .coordinator
                        .start_or_resume(options.clone(), now_unix)
                        .map_err(|error| CommandError::new("connection_busy", error.to_string()))?
                    else {
                        return Err(CommandError::new(
                            "connection_busy",
                            "Не удалось начать новое подключение",
                        ));
                    };
                    initialize_episode(&mut state, options, generation, now_unix);
                    state.initial_preflight = initial_preflight;
                    StartRuntimeAction::Run(generation)
                }
                StartDisposition::Recovering {
                    generation,
                    next_retry_at_unix: _,
                } => {
                    let action = recovering_action(
                        previous_generation,
                        generation,
                        state.next_retry_at_unix,
                    );
                    if action == StartRuntimeAction::Run(generation) {
                        initialize_episode(&mut state, options, generation, now_unix);
                        state.initial_preflight = initial_preflight;
                    }
                    action
                }
            }
        };
        let generation = match action {
            StartRuntimeAction::Run(generation) => generation,
            StartRuntimeAction::Wait(next_retry_at_unix) => {
                return Ok(StartCommandResponse::recovering(next_retry_at_unix));
            }
        };
        self.diagnostics
            .record_connection_intent(ConnectionIntentDiagnosticEvent::Started);
        self.run_attempt(generation).await
    }

    pub(crate) async fn cancel(&self) -> bool {
        let cancelled = {
            let mut state = self.state.lock().await;
            let generation = state.coordinator.generation();
            let cancelled = state.coordinator.cancel_intent(generation);
            if cancelled {
                state.options = None;
                state.policy = RecoveryPolicyContext::default();
                state.next_retry_at_unix = None;
                state.retry_not_before_unix = None;
                state.reconcile_before_attempt = false;
                state.repair_before_attempt = false;
                state.refresh_capability_before_attempt = false;
                state.armed = false;
                state.diagnostics_episode.reset();
                state.attempt_kind = AttemptKind::Start;
                state.retry_count = 0;
                state.owned_lease_id = None;
                state.initial_preflight = None;
            }
            cancelled
        };
        if cancelled {
            self.diagnostics
                .record_connection_intent(ConnectionIntentDiagnosticEvent::Cancelled);
            self.wake.notify_one();
        }
        cancelled
    }

    pub(crate) async fn wake_for_network_change(&self) -> bool {
        let woke = {
            let mut state = self.state.lock().await;
            state.coordinator.wake_for_network_change()
        };
        if woke {
            self.diagnostics
                .record_connection_intent(ConnectionIntentDiagnosticEvent::NetworkWakeup);
            self.wake.notify_one();
        }
        woke
    }

    #[cfg(target_os = "macos")]
    pub(crate) async fn handle_stall(&self, lease_id: &str) -> bool {
        let (options, generation) = {
            let state = self.state.lock().await;
            let Some(options) = state.options.clone() else {
                return false;
            };
            if !can_begin_stall_recovery(state.coordinator.status(), state.armed) {
                return true;
            }
            if state.owned_lease_id.as_deref() != Some(lease_id) {
                return false;
            }
            (options, state.coordinator.generation())
        };
        let current = self.application.state().await.connection;
        let Some(current) = current.filter(|connection| connection.lease_id == lease_id) else {
            return false;
        };
        let pinned = current.pinned;
        let transport = self
            .application
            .connection_recovery_transport(lease_id)
            .unwrap_or(RecoveryTransport::Other);
        let plan = nelomai_client_core::stall_recovery_plan(&options, pinned, transport);

        if self
            .recover_current_connection_locally(generation, lease_id)
            .await
            .is_some()
        {
            return true;
        }

        let generation = {
            let mut state = self.state.lock().await;
            if state
                .coordinator
                .handle_stall(
                    generation,
                    StallTrigger {
                        options: options.clone(),
                        pinned,
                        transport,
                    },
                )
                .is_err()
            {
                return true;
            }
            let generation = state.coordinator.generation();
            state.attempt_kind = attempt_kind_for_stall_plan(plan);
            state.refresh_capability_before_attempt = true;
            state.next_retry_at_unix = None;
            state.retry_not_before_unix = None;
            consume_immediate_retry_slot(
                &mut state.coordinator,
                generation,
                crate::current_unix_time(),
            );
            generation
        };
        self.diagnostics
            .record_connection_intent(ConnectionIntentDiagnosticEvent::LeaseReplacementStarted);
        let _ = self.run_attempt(generation).await;
        true
    }

    #[cfg(target_os = "macos")]
    async fn recover_current_connection_locally(
        &self,
        generation: IntentGeneration,
        lease_id: &str,
    ) -> Option<Connection> {
        let rebind = self
            .application
            .recover_stalled_data_plane(lease_id, StalledDataPlaneRecovery::RebindUdp)
            .await;
        if matches!(rebind, Ok(StalledDataPlaneRecoveryOutcome::Rebound)) {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if self
                .application
                .probe_fresh_connection_latency_ms(&format!("{}/health", crate::PANEL_BASE))
                .await
                .is_some()
            {
                return self
                    .accept_local_recovery(
                        generation,
                        lease_id,
                        "connection.intent.stall_recovered_after_rebind",
                    )
                    .await;
            }
        }

        let local_restart = self
            .application
            .recover_stalled_data_plane(lease_id, StalledDataPlaneRecovery::RestartLocalTunnel)
            .await;
        if matches!(
            local_restart,
            Ok(StalledDataPlaneRecoveryOutcome::Reconnected)
        ) && self
            .application
            .probe_fresh_connection_latency_ms(&format!("{}/health", crate::PANEL_BASE))
            .await
            .is_some()
        {
            return self
                .accept_local_recovery(
                    generation,
                    lease_id,
                    "connection.intent.stall_recovered_after_local_restart",
                )
                .await;
        }
        None
    }

    #[cfg(target_os = "macos")]
    async fn accept_local_recovery(
        &self,
        generation: IntentGeneration,
        lease_id: &str,
        event: &str,
    ) -> Option<Connection> {
        let core_state = self.application.state().await;
        let state = self.state.lock().await;
        let connection = local_recovery_connection(
            &core_state,
            generation,
            state.coordinator.generation(),
            state.armed,
            state.owned_lease_id.as_deref(),
            lease_id,
        );
        if connection.is_some() {
            record_recovery_success(&self.diagnostics, lease_id, Some(event));
        }
        connection
    }

    async fn scheduler_loop(self: Arc<Self>) {
        loop {
            let sleep_seconds = {
                let mut state = self.state.lock().await;
                if state.coordinator.take_network_wakeup() {
                    let now = crate::current_unix_time();
                    state.next_retry_at_unix =
                        Some(retry_at_after_wakeup(state.retry_not_before_unix, now));
                }
                match (state.coordinator.status(), state.next_retry_at_unix) {
                    (ConnectionIntentStatus::Recovering, Some(next)) => {
                        Some(next.saturating_sub(crate::current_unix_time()).max(0) as u64)
                    }
                    _ => None,
                }
            };
            let Some(sleep_seconds) = sleep_seconds else {
                self.wake.notified().await;
                continue;
            };
            if sleep_seconds > 0 {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(sleep_seconds)) => {}
                    _ = self.wake.notified() => { continue; }
                }
            }
            let generation = {
                let state = self.state.lock().await;
                (state.coordinator.status() == ConnectionIntentStatus::Recovering
                    && state
                        .next_retry_at_unix
                        .is_some_and(|next| next <= crate::current_unix_time()))
                .then(|| state.coordinator.generation())
            };
            if let Some(generation) = generation {
                let _ = self.run_attempt(generation).await;
            }
        }
    }

    async fn run_attempt(
        &self,
        generation: IntentGeneration,
    ) -> Result<StartCommandResponse, CommandError> {
        let (
            mut options,
            reconcile_before_attempt,
            repair_before_attempt,
            attempt_kind,
            refresh_capability_before_attempt,
            initial_preflight,
        ) = {
            let mut state = self.state.lock().await;
            let options = state.options.clone().ok_or_else(|| {
                if state.coordinator.generation() != generation
                    || state.coordinator.status() == ConnectionIntentStatus::None
                {
                    CommandError::new("connection_intent_cancelled", "Подключение отменено")
                } else {
                    CommandError::new(
                        "connection_intent_unavailable",
                        "Параметры восстановления недоступны",
                    )
                }
            })?;
            if !state.coordinator.begin_attempt(generation) {
                return Ok(StartCommandResponse::recovering(state.next_retry_at_unix));
            }
            state.next_retry_at_unix = None;
            state.retry_not_before_unix = None;
            (
                options,
                std::mem::take(&mut state.reconcile_before_attempt),
                std::mem::take(&mut state.repair_before_attempt),
                state.attempt_kind,
                state.refresh_capability_before_attempt,
                state.initial_preflight.clone(),
            )
        };
        if let Some(initial_preflight) = initial_preflight {
            let (start_mode, resolved_options) =
                match self.resolve_initial_desktop_start(&initial_preflight).await {
                    Ok(resolved) => resolved,
                    Err(error) => return self.complete_error(generation, error).await,
                };
            {
                let mut state = self.state.lock().await;
                if !attempt_is_current_after_async_boundary(&mut state.coordinator, generation) {
                    return Err(CommandError::new(
                        "connection_intent_cancelled",
                        "Подключение отменено",
                    ));
                }
                if let Some(resolved_options) = resolved_options {
                    if !state
                        .coordinator
                        .replace_active_options(generation, resolved_options.clone())
                    {
                        return Err(CommandError::new(
                            "connection_intent_cancelled",
                            "Подключение отменено",
                        ));
                    }
                    state.options = Some(resolved_options.clone());
                    options = resolved_options;
                }
            }
            let preflight = self
                .run_initial_desktop_preflight(&options, &initial_preflight)
                .await;
            match initial_desktop_preflight_action(start_mode, preflight.is_ok()) {
                InitialDesktopPreflightAction::RetryIntent => {
                    return self
                        .complete_error(
                            generation,
                            preflight.expect_err("retry requires a failed preflight"),
                        )
                        .await;
                }
                InitialDesktopPreflightAction::ContinueRecovery => {
                    let mut state = self.state.lock().await;
                    if !attempt_is_current_after_async_boundary(&mut state.coordinator, generation)
                    {
                        return Err(CommandError::new(
                            "connection_intent_cancelled",
                            "Подключение отменено",
                        ));
                    }
                    state.initial_preflight = None;
                }
                InitialDesktopPreflightAction::RunLegacy => {
                    let skip_probe_refresh = initial_preflight
                        .quick_toggle_skip_probe_refresh
                        .unwrap_or(false);
                    self.abandon_initial_intent_for_legacy(generation).await?;
                    let result = if skip_probe_refresh {
                        self.application
                            .start_without_probe_refresh(options, crate::current_unix_time())
                            .await
                    } else {
                        self.application
                            .start(options, crate::current_unix_time())
                            .await
                    };
                    return result
                        .map(StartCommandResponse::connected)
                        .map_err(CommandError::from);
                }
            }
        }
        if refresh_capability_before_attempt {
            if let Err(error) = self.refresh_recovery_capability().await {
                return self.complete_error(generation, error).await;
            }
            let mut state = self.state.lock().await;
            if !attempt_is_current_after_async_boundary(&mut state.coordinator, generation) {
                return Err(CommandError::new(
                    "connection_intent_cancelled",
                    "Подключение отменено",
                ));
            }
            state.refresh_capability_before_attempt = false;
        }
        if reconcile_before_attempt {
            if let Err(error) = self
                .application
                .reconcile_pending_operation_for_retry()
                .await
            {
                self.state.lock().await.reconcile_before_attempt = true;
                return self.complete_error(generation, error).await;
            }
            let mut state = self.state.lock().await;
            if !attempt_is_current_after_async_boundary(&mut state.coordinator, generation) {
                return Err(CommandError::new(
                    "connection_intent_cancelled",
                    "Подключение отменено",
                ));
            }
        }
        if repair_before_attempt {
            let _ = crate::platform::prepare_tunnel(self.app.clone()).await;
        }
        let result = match attempt_kind {
            AttemptKind::Start => {
                self.application
                    .connection_intent_attempt(options, crate::current_unix_time())
                    .await
            }
            AttemptKind::StallReplacement => {
                self.application
                    .replace_stalled_connection(options, crate::current_unix_time())
                    .await
            }
        };
        if result.is_err() && attempt_kind == AttemptKind::StallReplacement {
            let terminal_old_lease =
                self.application
                    .state()
                    .await
                    .connection
                    .is_some_and(|connection| {
                        matches!(
                            connection.status,
                            LeaseStatus::Released | LeaseStatus::Failed
                        )
                    });
            if terminal_old_lease {
                self.state.lock().await.attempt_kind = AttemptKind::Start;
            }
        }
        match result {
            Ok(connection) => self.complete_success(generation, connection).await,
            Err(error) => self.complete_error(generation, error).await,
        }
    }

    async fn refresh_recovery_capability(&self) -> Result<(), ApplicationError> {
        let now_unix = crate::current_unix_time();
        let bootstrap = self.application.bootstrap(now_unix).await?;
        recovery_capability_result(bootstrap.capabilities.as_ref(), now_unix)
    }

    async fn resolve_initial_desktop_start(
        &self,
        preflight: &InitialDesktopPreflight,
    ) -> Result<(InitialDesktopStartMode, Option<ConnectOptions>), ApplicationError> {
        let now_unix = crate::current_unix_time();
        let bootstrap = self.application.bootstrap(now_unix).await?;
        if let Some(expected_device_id) = preflight.expected_device_id.as_ref() {
            if bootstrap.device.id != *expected_device_id {
                return Err(ApplicationError::Core(CoreError::Api(
                    CoreApiError::Rejected {
                        code: "device_mismatch".to_string(),
                        message: "Подключение запрошено для другого устройства".to_string(),
                        retry_after_seconds: None,
                    },
                )));
            }
        }
        let resolved_options = if preflight.quick_toggle_skip_probe_refresh.is_some() {
            if !bootstrap.access.can_connect {
                return Err(ApplicationError::Core(CoreError::AccessExpired));
            }
            let binding_egress_mode = bootstrap
                .binding
                .as_ref()
                .map(|binding| binding.egress_mode)
                .ok_or_else(|| {
                    ApplicationError::Core(CoreError::Api(CoreApiError::Rejected {
                        code: "peer_binding_required".to_string(),
                        message: "Сначала выберите пир в приложении".to_string(),
                        retry_after_seconds: None,
                    }))
                })?;
            Some(ConnectOptions {
                layer: bootstrap.defaults.layer,
                tic_connection_mode: bootstrap.defaults.tic_connection_mode,
                route_mode: bootstrap.defaults.route_mode,
                egress_mode: connection_egress_mode(
                    bootstrap.defaults.layer,
                    bootstrap.defaults.route_mode,
                    bootstrap.defaults.tic_connection_mode,
                    self.app.state::<Arc<AppPreferenceStore>>().get(),
                    binding_egress_mode,
                ),
                probes: Vec::new(),
                allow_alternate: true,
            })
        } else {
            None
        };
        Ok((
            initial_desktop_start_mode(bootstrap.capabilities.as_ref(), now_unix),
            resolved_options,
        ))
    }

    async fn run_initial_desktop_preflight(
        &self,
        options: &ConnectOptions,
        preflight: &InitialDesktopPreflight,
    ) -> Result<(), ApplicationError> {
        if let Some(binding_request) = preflight.binding_request.as_ref() {
            self.application.bind_peer(binding_request.clone()).await?;
        }
        match crate::platform::prepare_tunnel(self.app.clone()).await {
            Ok(()) => self
                .diagnostics
                .record_named("tunnel.prepare_succeeded", None, None, None),
            Err(error) => {
                let error = CoreError::from(error);
                let error = ApplicationError::Core(error);
                let code = stable_error_code(&error);
                self.diagnostics
                    .record_named("tunnel.prepare_failed", None, None, Some(&code));
                return Err(error);
            }
        }
        #[cfg(windows)]
        if options.layer == nelomai_contracts::Layer::Stray {
            crate::commands::ensure_defender_ready_for_awg(&self.diagnostics).await?;
        }
        crate::commands::refresh_installed_applications_before_start(
            &self.app,
            &self.application,
            options.layer,
            options.route_mode,
        )
        .await
    }

    async fn abandon_initial_intent_for_legacy(
        &self,
        generation: IntentGeneration,
    ) -> Result<(), CommandError> {
        let mut state = self.state.lock().await;
        if !state.coordinator.cancel_intent(generation) {
            return Err(CommandError::new(
                "connection_intent_cancelled",
                "Подключение отменено",
            ));
        }
        state.coordinator.complete_compensation(generation);
        state.options = None;
        state.policy = RecoveryPolicyContext::default();
        state.next_retry_at_unix = None;
        state.retry_not_before_unix = None;
        state.reconcile_before_attempt = false;
        state.repair_before_attempt = false;
        state.refresh_capability_before_attempt = false;
        state.initial_preflight = None;
        state.diagnostics_episode.reset();
        state.attempt_kind = AttemptKind::Start;
        state.retry_count = 0;
        state.owned_lease_id = None;
        Ok(())
    }

    async fn complete_success(
        &self,
        generation: IntentGeneration,
        connection: Connection,
    ) -> Result<StartCommandResponse, CommandError> {
        let (decision, recovered) = {
            let mut state = self.state.lock().await;
            let recovered = attempt_reports_recovery(state.attempt_kind, state.retry_count);
            let decision = state
                .coordinator
                .mark_connected(generation, connection.clone());
            if decision == RecoveryDecision::Accept {
                state.next_retry_at_unix = None;
                state.retry_not_before_unix = None;
                state.policy = RecoveryPolicyContext::default();
                state.refresh_capability_before_attempt = false;
                state.armed = true;
                state.diagnostics_episode.reset();
                state.attempt_kind = AttemptKind::Start;
                state.retry_count = 0;
                state.owned_lease_id = Some(connection.lease_id.clone());
                state.initial_preflight = None;
            }
            (decision, recovered)
        };
        if decision == RecoveryDecision::Accept {
            if recovered {
                record_recovery_success(&self.diagnostics, &connection.lease_id, None);
            }
            self.emit_change(None);
            return Ok(StartCommandResponse::connected(connection));
        }

        self.compensate_stale_success(generation).await?;
        Err(CommandError::new(
            "connection_intent_cancelled",
            "Подключение отменено",
        ))
    }

    async fn compensate_stale_success(
        &self,
        generation: IntentGeneration,
    ) -> Result<(), CommandError> {
        let delays = [0_u64, 2, 5, 15, 30, 60, 300];
        let mut retry = 0_usize;
        loop {
            match self
                .application
                .compensate_stale_connection_intent_result()
                .await
            {
                Ok(()) => {
                    let mut state = self.state.lock().await;
                    state.coordinator.complete_compensation(generation);
                    return Ok(());
                }
                Err(error) => {
                    retry = retry.saturating_add(1);
                    let delay = delays[retry.min(delays.len() - 1)];
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                    }
                    if retry == 1 {
                        self.diagnostics.record_named(
                            "connection.intent.compensation_retry",
                            None,
                            None,
                            Some(&stable_error_code(&error)),
                        );
                    }
                }
            }
        }
    }

    async fn complete_error(
        &self,
        generation: IntentGeneration,
        error: ApplicationError,
    ) -> Result<StartCommandResponse, CommandError> {
        let code = stable_error_code(&error);
        let retry_after_seconds = error_retry_after_seconds(&error);
        let command_error = CommandError::from(error);
        let reason_class = ConnectionIntentReasonClass::from_code(&code);
        let (decision, next_retry_at_unix, diagnostic_actions, retry_count, delay_seconds) = {
            let mut state = self.state.lock().await;
            state.policy.retry_after_seconds = retry_after_seconds;
            let decision = classify_recovery(&code, state.policy);
            state.refresh_capability_before_attempt = next_capability_refresh_requirement(
                state.refresh_capability_before_attempt,
                decision,
            );
            if decision == RecoveryDecision::Terminal {
                let armed = state.armed;
                if !state.coordinator.mark_terminal(generation, armed) {
                    state.coordinator.complete_compensation(generation);
                    return Err(CommandError::new(
                        "connection_intent_cancelled",
                        "Подключение отменено",
                    ));
                }
                state.next_retry_at_unix = None;
                state.retry_not_before_unix = None;
                if !armed {
                    state.options = None;
                    state.initial_preflight = None;
                }
                let actions = state.diagnostics_episode.observe_terminal();
                (decision, None, actions, state.retry_count, 0)
            } else {
                if state.coordinator.accept_result(generation)
                    == RecoveryDecision::DiscardAndCompensate
                {
                    state.coordinator.complete_compensation(generation);
                    return Err(CommandError::new(
                        "connection_intent_cancelled",
                        "Подключение отменено",
                    ));
                }
                update_policy_context(&mut state.policy, &code, decision);
                state.reconcile_before_attempt =
                    next_reconcile_requirement(state.reconcile_before_attempt, decision);
                state.repair_before_attempt = matches!(
                    decision,
                    RecoveryDecision::RetryOnce | RecoveryDecision::RestartLocalTunnel
                );
                let now = crate::current_unix_time();
                let next = match decision {
                    RecoveryDecision::RetryAfter(delay) => {
                        Some(now.saturating_add(i64::try_from(delay).unwrap_or(i64::MAX)))
                    }
                    _ => state.coordinator.schedule_retry(generation, now),
                };
                state.next_retry_at_unix = next;
                state.retry_not_before_unix = match decision {
                    RecoveryDecision::RetryAfter(_) => next,
                    _ => None,
                };
                state.retry_count = state.retry_count.saturating_add(1);
                let delay_seconds = next
                    .map(|next| next.saturating_sub(now).max(0) as u64)
                    .unwrap_or_default();
                let actions = state.diagnostics_episode.observe_retry(delay_seconds);
                (decision, next, actions, state.retry_count, delay_seconds)
            }
        };
        if decision == RecoveryDecision::Terminal {
            self.diagnostics.record_connection_intent(
                ConnectionIntentDiagnosticEvent::TerminalFailure { reason_class },
            );
            self.queue_connection_intent_report(
                diagnostic_actions,
                ConnectionIntentReportTrigger::TerminalFailure,
            )
            .await;
            self.emit_change(Some(command_error.clone()));
            return Err(command_error);
        }
        self.diagnostics.record_connection_intent(
            ConnectionIntentDiagnosticEvent::RetryScheduled {
                attempt: retry_count,
                reason_class,
                delay_seconds,
            },
        );
        self.queue_connection_intent_report(
            diagnostic_actions,
            ConnectionIntentReportTrigger::SlowRecovery,
        )
        .await;
        if diagnostic_actions.notify_user {
            self.diagnostics.record_connection_intent(
                ConnectionIntentDiagnosticEvent::SlowRecoveryNotified { reason_class },
            );
            self.emit_slow_recovery_notification();
        }
        self.emit_change(None);
        self.wake.notify_one();
        Ok(StartCommandResponse::recovering(next_retry_at_unix))
    }

    fn emit_change(&self, error: Option<CommandError>) {
        let _ = self.app.emit(
            "native-connection-changed",
            NativeConnectionChangedEvent {
                error,
                action: "start",
            },
        );
    }

    async fn queue_connection_intent_report(
        &self,
        actions: ConnectionIntentDiagnosticActions,
        trigger: ConnectionIntentReportTrigger,
    ) {
        if !actions.queue_report {
            return;
        }
        if let Err(error) = self
            .diagnostics
            .queue_connection_intent_report(trigger, crate::current_unix_time())
        {
            self.state
                .lock()
                .await
                .diagnostics_episode
                .report_queue_failed();
            self.diagnostics.record_named(
                "diagnostics.connection_intent_report_queue_failed",
                None,
                None,
                Some(&error.kind().to_string()),
            );
        }
    }

    fn emit_slow_recovery_notification(&self) {
        const TITLE: &str = "Проверяем подключение";
        const BODY: &str = "Приложение проверяет стабильность подключения и при необходимости повторит попытку автоматически.";
        if show_slow_recovery_notification(self.notifier.as_ref()).is_err() {
            self.diagnostics.record_named(
                "diagnostics.connection_intent_notification_failed",
                None,
                None,
                Some("notification_unavailable"),
            );
        }
        let _ = self.app.emit(
            "native-connection-intent-notification",
            NativeConnectionIntentNotificationEvent {
                kind: "slow_recovery",
                title: TITLE,
                body: BODY,
            },
        );
    }
}

fn initialize_episode(
    state: &mut RuntimeState,
    options: ConnectOptions,
    generation: IntentGeneration,
    now_unix: i64,
) {
    state.options = Some(options.normalized_for_layer());
    state.policy = RecoveryPolicyContext::default();
    state.next_retry_at_unix = None;
    state.retry_not_before_unix = None;
    state.reconcile_before_attempt = false;
    state.repair_before_attempt = false;
    state.diagnostics_episode.reset();
    state.retry_count = 0;
    if !state.armed {
        state.attempt_kind = AttemptKind::Start;
    }
    consume_immediate_retry_slot(&mut state.coordinator, generation, now_unix);
}

fn retry_at_after_wakeup(retry_not_before_unix: Option<i64>, now_unix: i64) -> i64 {
    retry_not_before_unix.unwrap_or(now_unix).max(now_unix)
}

fn recovering_action(
    previous_generation: IntentGeneration,
    generation: IntentGeneration,
    next_retry_at_unix: Option<i64>,
) -> StartRuntimeAction {
    if generation == previous_generation {
        StartRuntimeAction::Wait(next_retry_at_unix)
    } else {
        StartRuntimeAction::Run(generation)
    }
}

fn consume_immediate_retry_slot(
    coordinator: &mut ConnectionIntentCoordinator,
    generation: IntentGeneration,
    now_unix: i64,
) {
    // The active attempt consumes the zero-second schedule entry so its first
    // failure waits two seconds instead of launching a duplicate immediately.
    let _ = coordinator.schedule_retry(generation, now_unix);
}

fn connection_matches_core_state(state: &CoreState, connection: &Connection) -> bool {
    state.phase == Phase::Connected
        && state
            .connection
            .as_ref()
            .is_some_and(|current| current.lease_id == connection.lease_id)
}

#[cfg(any(target_os = "macos", test))]
fn can_begin_stall_recovery(status: ConnectionIntentStatus, armed: bool) -> bool {
    armed && status == ConnectionIntentStatus::None
}

fn attempt_is_current_after_async_boundary(
    coordinator: &mut ConnectionIntentCoordinator,
    generation: IntentGeneration,
) -> bool {
    if coordinator.generation() == generation
        && coordinator.status() != ConnectionIntentStatus::None
    {
        return true;
    }
    coordinator.complete_compensation(generation);
    false
}

#[cfg(any(target_os = "macos", test))]
fn attempt_kind_for_stall_plan(plan: StallRecoveryPlan) -> AttemptKind {
    match plan {
        StallRecoveryPlan::ReplaceDynamic { .. } | StallRecoveryPlan::PreservePeer => {
            AttemptKind::StallReplacement
        }
    }
}

fn attempt_reports_recovery(attempt_kind: AttemptKind, retry_count: u32) -> bool {
    retry_count > 0 || attempt_kind != AttemptKind::Start
}

fn next_capability_refresh_requirement(current: bool, decision: RecoveryDecision) -> bool {
    current || decision == RecoveryDecision::RetryNewOperation
}

fn next_reconcile_requirement(current: bool, decision: RecoveryDecision) -> bool {
    current
        || matches!(
            decision,
            RecoveryDecision::ReconcileThenRetry | RecoveryDecision::ReconcileOnce
        )
}

fn recovery_capability_result(
    capability: Option<&ConnectionIntentCapability>,
    now_unix: i64,
) -> Result<(), ApplicationError> {
    if allows_new_connection_intent_operation(capability, now_unix) {
        return Ok(());
    }
    Err(ApplicationError::Core(CoreError::Api(
        CoreApiError::Rejected {
            code: "recovery_contract_unavailable".to_string(),
            message: "Автоматическое восстановление временно недоступно".to_string(),
            retry_after_seconds: None,
        },
    )))
}

fn initial_desktop_start_mode(
    capability: Option<&ConnectionIntentCapability>,
    now_unix: i64,
) -> InitialDesktopStartMode {
    if allows_new_connection_intent_operation(capability, now_unix) {
        InitialDesktopStartMode::Recovery
    } else {
        InitialDesktopStartMode::Legacy
    }
}

fn quick_toggle_placeholder_options() -> ConnectOptions {
    ConnectOptions {
        layer: nelomai_contracts::Layer::Stray,
        tic_connection_mode: nelomai_contracts::TicConnectionMode::Dynamic,
        route_mode: nelomai_contracts::RouteMode::Standalone,
        egress_mode: nelomai_contracts::EgressMode::Ipv4,
        probes: Vec::new(),
        allow_alternate: true,
    }
}

fn initial_desktop_preflight_action(
    start_mode: InitialDesktopStartMode,
    preflight_succeeded: bool,
) -> InitialDesktopPreflightAction {
    match (start_mode, preflight_succeeded) {
        (_, false) => InitialDesktopPreflightAction::RetryIntent,
        (InitialDesktopStartMode::Recovery, true) => {
            InitialDesktopPreflightAction::ContinueRecovery
        }
        (InitialDesktopStartMode::Legacy, true) => InitialDesktopPreflightAction::RunLegacy,
    }
}

#[cfg(any(target_os = "macos", test))]
fn local_recovery_connection(
    core_state: &CoreState,
    expected_generation: IntentGeneration,
    current_generation: IntentGeneration,
    armed: bool,
    owned_lease_id: Option<&str>,
    lease_id: &str,
) -> Option<Connection> {
    if expected_generation != current_generation
        || !armed
        || owned_lease_id != Some(lease_id)
        || core_state.phase != Phase::Connected
    {
        return None;
    }
    core_state
        .connection
        .clone()
        .filter(|connection| connection.lease_id == lease_id)
}

fn record_recovery_success(
    diagnostics: &AppDiagnostics,
    lease_id: &str,
    specialized_event: Option<&str>,
) {
    if let Some(event) = specialized_event {
        diagnostics.record_named(event, Some(lease_id), None, None);
    }
    diagnostics.record_connection_intent(ConnectionIntentDiagnosticEvent::Recovered);
}

fn update_policy_context(
    context: &mut RecoveryPolicyContext,
    code: &str,
    decision: RecoveryDecision,
) {
    if decision == RecoveryDecision::ReconcileOnce {
        context.stalled_reconcile_attempted = true;
        return;
    }
    if decision != RecoveryDecision::RetryOnce {
        return;
    }
    match code {
        "service_unavailable" => context.service_recovery_attempted = true,
        "amneziawg_profile_mismatch"
        | "awg3_profile_apply_failed"
        | "awg3_profile_transform_mismatch" => context.profile_reissue_attempted = true,
        _ => {}
    }
}

fn stable_error_code(error: &ApplicationError) -> String {
    fn api_code(error: &CoreApiError) -> String {
        match error {
            CoreApiError::Unauthorized => "signed_out".to_string(),
            CoreApiError::AccessExpired => "access_expired".to_string(),
            CoreApiError::Retryable => "transport_error".to_string(),
            CoreApiError::Rejected { code, .. } => code.clone(),
        }
    }

    match error {
        ApplicationError::Storage => "storage_unavailable".to_string(),
        ApplicationError::Clock => "clock_unavailable".to_string(),
        ApplicationError::Api(error) => api_code(error),
        ApplicationError::Core(error) => match error {
            CoreError::SignedOut => "signed_out".to_string(),
            CoreError::AccessExpired => "access_expired".to_string(),
            CoreError::UpdateRequired => "update_required".to_string(),
            CoreError::SavedConnectionUnavailable => "saved_connection_unavailable".to_string(),
            CoreError::StartCancelled => "connection_intent_cancelled".to_string(),
            CoreError::Storage => "storage_unavailable".to_string(),
            CoreError::Api(error) => api_code(error),
            CoreError::Tunnel(code) | CoreError::SplitTunnel(code) => code.clone(),
        },
    }
}

fn error_retry_after_seconds(error: &ApplicationError) -> Option<u64> {
    fn core(error: &CoreApiError) -> Option<u64> {
        match error {
            CoreApiError::Rejected {
                retry_after_seconds,
                ..
            } => *retry_after_seconds,
            _ => None,
        }
    }

    match error {
        ApplicationError::Api(error) => core(error),
        ApplicationError::Core(CoreError::Api(error)) => core(error),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        attempt_is_current_after_async_boundary, attempt_kind_for_stall_plan,
        attempt_reports_recovery, can_begin_stall_recovery, connection_matches_core_state,
        consume_immediate_retry_slot, error_retry_after_seconds, initial_desktop_preflight_action,
        initial_desktop_start_mode, local_recovery_connection, next_capability_refresh_requirement,
        next_reconcile_requirement, quick_toggle_placeholder_options, record_recovery_success,
        recovering_action, recovery_capability_result, retry_at_after_wakeup,
        show_slow_recovery_notification, stable_error_code, update_policy_context, AttemptKind,
        InitialDesktopPreflightAction, InitialDesktopStartMode, SlowRecoveryNotifier,
        StartRuntimeAction,
    };
    use crate::{diagnostics::AppDiagnostics, resource_usage::ResourceSnapshot};
    use nelomai_client_application::ApplicationError;
    use nelomai_client_core::{
        classify_recovery, ConnectOptions, ConnectionIntentCoordinator, CoreApiError, CoreError,
        CoreState, IntentGeneration, Phase, RecoveryDecision, RecoveryPolicyContext,
        StartDisposition,
    };
    use nelomai_contracts::{
        Connection, ConnectionIntentCapability, EgressMode, Layer, LeaseStatus, RouteMode,
        TicConnectionMode,
    };

    struct CountingNotifier(std::sync::atomic::AtomicUsize);

    impl SlowRecoveryNotifier for CountingNotifier {
        fn show(&self, title: &str, body: &str) -> Result<(), String> {
            assert_eq!(title, "Проверяем подключение");
            assert!(body.contains("автоматически"));
            assert!(!body.contains("недоступна"));
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn slow_recovery_system_notification_uses_injectable_notifier() {
        let notifier = CountingNotifier(std::sync::atomic::AtomicUsize::new(0));
        show_slow_recovery_notification(&notifier).unwrap();
        assert_eq!(notifier.0.load(std::sync::atomic::Ordering::SeqCst), 1,);
    }

    fn connection(lease_id: &str) -> Connection {
        Connection {
            lease_id: lease_id.to_string(),
            pool_id: Some("pool".to_string()),
            layer: Layer::Stray,
            transport_protocol: Default::default(),
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            egress_mode: EgressMode::Ipv4,
            probe_url: None,
            status: LeaseStatus::Connected,
            pinned: false,
            stopped_at: None,
        }
    }

    #[test]
    fn retryable_transport_and_stable_backend_codes_feed_the_shared_classifier() {
        assert_eq!(
            stable_error_code(&ApplicationError::Core(CoreError::Api(
                CoreApiError::Retryable,
            ))),
            "transport_error"
        );
        assert_eq!(
            stable_error_code(&ApplicationError::Core(CoreError::Tunnel(
                "service_unavailable".to_string(),
            ))),
            "service_unavailable"
        );
    }

    #[test]
    fn bounded_retry_after_reaches_the_runtime_policy() {
        let error = ApplicationError::Core(CoreError::Api(CoreApiError::Rejected {
            code: "connection_stall_recycle_rate_limited".to_string(),
            message: "retry later".to_string(),
            retry_after_seconds: Some(120),
        }));

        assert_eq!(error_retry_after_seconds(&error), Some(120));
    }

    #[test]
    fn reconcile_once_is_bounded_after_the_first_attempt() {
        let mut context = RecoveryPolicyContext::default();
        let first = classify_recovery("connection_stall_not_recyclable", context);
        assert_eq!(first, RecoveryDecision::ReconcileOnce);
        update_policy_context(&mut context, "connection_stall_not_recyclable", first);
        assert_eq!(
            classify_recovery("connection_stall_not_recyclable", context),
            RecoveryDecision::Terminal
        );
    }

    #[test]
    fn nonterminal_server_reconcile_result_keeps_reconcile_as_the_next_action() {
        assert!(next_reconcile_requirement(
            true,
            RecoveryDecision::RetryAfter(1)
        ));
        assert!(next_reconcile_requirement(
            true,
            RecoveryDecision::RetrySameOperation
        ));
        assert!(next_reconcile_requirement(
            false,
            RecoveryDecision::ReconcileThenRetry
        ));
        assert!(!next_reconcile_requirement(
            false,
            RecoveryDecision::RetryAfter(1)
        ));
    }

    #[test]
    fn immediate_attempt_consumes_zero_delay_for_initial_and_stall_recovery() {
        let mut coordinator = ConnectionIntentCoordinator::default();
        let options = ConnectOptions {
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            egress_mode: EgressMode::Ipv4,
            probes: Vec::new(),
            allow_alternate: true,
        };
        let StartDisposition::Recovering { generation, .. } =
            coordinator.start_or_resume(options, 100).unwrap()
        else {
            panic!("expected recovering intent");
        };

        consume_immediate_retry_slot(&mut coordinator, generation, 100);

        assert_eq!(coordinator.schedule_retry(generation, 100), Some(102));
    }

    #[test]
    fn repeated_start_waits_for_the_existing_generation_instead_of_bypassing_backoff() {
        let mut coordinator = ConnectionIntentCoordinator::default();
        let options = ConnectOptions {
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            egress_mode: EgressMode::Ipv4,
            probes: Vec::new(),
            allow_alternate: true,
        };
        let StartDisposition::Recovering { generation, .. } =
            coordinator.start_or_resume(options, 100).unwrap()
        else {
            panic!("expected recovering intent");
        };

        assert_eq!(
            recovering_action(generation, generation, Some(102)),
            StartRuntimeAction::Wait(Some(102)),
        );
    }

    #[test]
    fn network_wakeup_never_shortens_a_server_retry_deadline() {
        assert_eq!(retry_at_after_wakeup(Some(130), 100), 130);
        assert_eq!(retry_at_after_wakeup(Some(90), 100), 100);
        assert_eq!(retry_at_after_wakeup(None, 100), 100);
    }

    #[test]
    fn cached_connected_result_must_match_the_current_core_lease() {
        let cached = connection("lease-old");
        assert!(connection_matches_core_state(
            &CoreState {
                phase: Phase::Connected,
                connection: Some(cached.clone()),
            },
            &cached,
        ));
        assert!(!connection_matches_core_state(
            &CoreState {
                phase: Phase::Ready,
                connection: Some(cached.clone()),
            },
            &cached,
        ));
        assert!(!connection_matches_core_state(
            &CoreState {
                phase: Phase::Connected,
                connection: Some(connection("lease-new")),
            },
            &cached,
        ));
    }

    #[test]
    fn blocked_or_active_recovery_cannot_be_rearmed_by_metrics() {
        assert!(can_begin_stall_recovery(
            nelomai_client_core::ConnectionIntentStatus::None,
            true,
        ));
        assert!(!can_begin_stall_recovery(
            nelomai_client_core::ConnectionIntentStatus::Recovering,
            true,
        ));
        assert!(!can_begin_stall_recovery(
            nelomai_client_core::ConnectionIntentStatus::BlockedTerminal,
            true,
        ));
    }

    #[test]
    fn preserved_peer_plan_uses_the_atomic_replacement_transaction() {
        assert_eq!(
            attempt_kind_for_stall_plan(nelomai_client_core::StallRecoveryPlan::PreservePeer),
            AttemptKind::StallReplacement,
        );
    }

    #[test]
    fn stall_replacement_reports_a_successful_recovery() {
        assert!(attempt_reports_recovery(AttemptKind::StallReplacement, 0));
    }

    #[test]
    fn capability_refresh_distinguishes_new_work_from_exact_replay() {
        assert!(next_capability_refresh_requirement(
            false,
            RecoveryDecision::RetryNewOperation,
        ));
        assert!(!next_capability_refresh_requirement(
            false,
            RecoveryDecision::RetrySameOperation,
        ));
        assert!(next_capability_refresh_requirement(
            true,
            RecoveryDecision::RetrySameOperation,
        ));
    }

    #[test]
    fn cancelled_capability_refresh_releases_the_attempt_for_the_next_start() {
        let mut coordinator = ConnectionIntentCoordinator::default();
        let options = ConnectOptions {
            layer: Layer::Stray,
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::Standalone,
            egress_mode: EgressMode::Ipv4,
            probes: Vec::new(),
            allow_alternate: true,
        };
        let StartDisposition::Recovering { generation, .. } =
            coordinator.start_or_resume(options.clone(), 100).unwrap()
        else {
            panic!("expected recovering intent");
        };
        assert!(coordinator.begin_attempt(generation));
        assert!(coordinator.cancel_intent(generation));

        assert!(!attempt_is_current_after_async_boundary(
            &mut coordinator,
            generation,
        ));
        assert!(matches!(
            coordinator.start_or_resume(options, 101).unwrap(),
            StartDisposition::Recovering { .. },
        ));
    }

    #[test]
    fn capability_refresh_accepts_only_a_present_enabled_unexpired_snapshot() {
        let enabled = ConnectionIntentCapability {
            revision: 7,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            connection_intent_recovery_v1: true,
        };
        assert!(recovery_capability_result(Some(&enabled), 100).is_ok());

        let disabled = ConnectionIntentCapability {
            connection_intent_recovery_v1: false,
            ..enabled
        };
        assert_eq!(
            stable_error_code(&recovery_capability_result(Some(&disabled), 100).unwrap_err()),
            "recovery_contract_unavailable",
        );
        assert_eq!(
            stable_error_code(&recovery_capability_result(None, 100).unwrap_err()),
            "recovery_contract_unavailable",
        );
    }

    #[test]
    fn initial_desktop_preflight_falls_back_to_legacy_only_after_authoritative_capability_check() {
        let enabled = ConnectionIntentCapability {
            revision: 7,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            connection_intent_recovery_v1: true,
        };
        assert_eq!(
            initial_desktop_start_mode(Some(&enabled), 100),
            InitialDesktopStartMode::Recovery,
        );

        let disabled = ConnectionIntentCapability {
            connection_intent_recovery_v1: false,
            ..enabled
        };
        assert_eq!(
            initial_desktop_start_mode(Some(&disabled), 100),
            InitialDesktopStartMode::Legacy,
        );
        assert_eq!(
            initial_desktop_start_mode(None, 100),
            InitialDesktopStartMode::Legacy,
        );
    }

    #[test]
    fn legacy_preflight_failure_retries_the_intent_before_one_successful_legacy_start() {
        assert_eq!(
            initial_desktop_preflight_action(InitialDesktopStartMode::Legacy, false),
            InitialDesktopPreflightAction::RetryIntent,
        );
        assert_eq!(
            initial_desktop_preflight_action(InitialDesktopStartMode::Legacy, true),
            InitialDesktopPreflightAction::RunLegacy,
        );

        let mut coordinator = ConnectionIntentCoordinator::default();
        let StartDisposition::Recovering { generation, .. } = coordinator
            .start_or_resume(
                ConnectOptions {
                    layer: Layer::Stray,
                    tic_connection_mode: TicConnectionMode::Dynamic,
                    route_mode: RouteMode::Standalone,
                    egress_mode: EgressMode::Ipv4,
                    probes: Vec::new(),
                    allow_alternate: true,
                },
                100,
            )
            .unwrap()
        else {
            panic!("expected recovering intent");
        };
        consume_immediate_retry_slot(&mut coordinator, generation, 100);
        assert!(coordinator.begin_attempt(generation));
        assert_eq!(
            coordinator.accept_result(generation),
            RecoveryDecision::Accept
        );
        assert_eq!(coordinator.schedule_retry(generation, 100), Some(102));
        assert_eq!(
            coordinator.status(),
            nelomai_client_core::ConnectionIntentStatus::Recovering
        );

        assert!(coordinator.begin_attempt(generation));
        let mut legacy_start_count = 0;
        if initial_desktop_preflight_action(InitialDesktopStartMode::Legacy, true)
            == InitialDesktopPreflightAction::RunLegacy
        {
            assert!(coordinator.cancel_intent(generation));
            legacy_start_count += 1;
        }
        assert_eq!(legacy_start_count, 1);
        assert_eq!(
            coordinator.status(),
            nelomai_client_core::ConnectionIntentStatus::None
        );
    }

    #[test]
    fn stop_cancels_legacy_fallback_while_transient_preflight_waits_for_retry() {
        let mut coordinator = ConnectionIntentCoordinator::default();
        let StartDisposition::Recovering { generation, .. } = coordinator
            .start_or_resume(
                ConnectOptions {
                    layer: Layer::Stray,
                    tic_connection_mode: TicConnectionMode::Dynamic,
                    route_mode: RouteMode::Standalone,
                    egress_mode: EgressMode::Ipv4,
                    probes: Vec::new(),
                    allow_alternate: true,
                },
                100,
            )
            .unwrap()
        else {
            panic!("expected recovering intent");
        };
        consume_immediate_retry_slot(&mut coordinator, generation, 100);
        assert!(coordinator.begin_attempt(generation));
        assert_eq!(
            initial_desktop_preflight_action(InitialDesktopStartMode::Legacy, false),
            InitialDesktopPreflightAction::RetryIntent,
        );
        assert_eq!(
            coordinator.accept_result(generation),
            RecoveryDecision::Accept
        );
        assert_eq!(coordinator.schedule_retry(generation, 100), Some(102));

        assert!(coordinator.cancel_intent(generation));
        assert_eq!(
            coordinator.status(),
            nelomai_client_core::ConnectionIntentStatus::None
        );
        assert!(!coordinator.begin_attempt(generation));
    }

    #[test]
    fn tray_preflight_failure_stays_owned_until_retry_resolves_real_options_once() {
        let mut coordinator = ConnectionIntentCoordinator::default();
        let StartDisposition::Recovering { generation, .. } = coordinator
            .start_or_resume(quick_toggle_placeholder_options(), 100)
            .unwrap()
        else {
            panic!("expected recovering tray intent");
        };
        consume_immediate_retry_slot(&mut coordinator, generation, 100);
        assert!(coordinator.begin_attempt(generation));
        assert_eq!(
            coordinator.accept_result(generation),
            RecoveryDecision::Accept
        );
        assert_eq!(coordinator.schedule_retry(generation, 100), Some(102));

        assert!(coordinator.begin_attempt(generation));
        let mut resolved = quick_toggle_placeholder_options();
        resolved.egress_mode = EgressMode::PreferIpv6;
        assert!(coordinator.replace_active_options(generation, resolved));
        assert!(coordinator.cancel_intent(generation));
        assert_eq!(
            coordinator.status(),
            nelomai_client_core::ConnectionIntentStatus::None
        );
    }

    #[test]
    fn installed_application_preflight_failure_is_retried_by_the_intent_policy() {
        assert_eq!(
            classify_recovery(
                "installed_applications_unavailable",
                RecoveryPolicyContext::default(),
            ),
            RecoveryDecision::RetrySameOperation,
        );
    }

    #[test]
    fn late_local_recovery_is_rejected_after_cancellation_or_core_stop() {
        let connected = CoreState {
            phase: Phase::Connected,
            connection: Some(connection("lease-1")),
        };
        assert!(local_recovery_connection(
            &connected,
            IntentGeneration::default(),
            IntentGeneration::default(),
            true,
            Some("lease-1"),
            "lease-1",
        )
        .is_some());

        let stopped = CoreState {
            phase: Phase::Ready,
            connection: Some(Connection {
                status: LeaseStatus::Released,
                ..connection("lease-1")
            }),
        };
        assert_eq!(
            local_recovery_connection(
                &stopped,
                IntentGeneration::default(),
                IntentGeneration::default(),
                true,
                Some("lease-1"),
                "lease-1",
            ),
            None,
        );
        assert_eq!(
            local_recovery_connection(
                &connected,
                IntentGeneration::default(),
                IntentGeneration::default(),
                false,
                None,
                "lease-1",
            ),
            None,
        );
    }

    #[test]
    fn immediate_stall_success_records_specialized_and_generic_recovery_events() {
        let directory = tempfile::tempdir().unwrap();
        let diagnostics = AppDiagnostics::new(
            directory.path().to_path_buf(),
            ResourceSnapshot::capture_for_test(),
        )
        .unwrap();

        record_recovery_success(
            &diagnostics,
            "lease-1",
            Some("connection.intent.stall_recovered_after_rebind"),
        );

        let report = diagnostics
            .build_report(ResourceSnapshot::capture_for_test())
            .unwrap();
        assert_eq!(
            report
                .application_log
                .lines()
                .filter(|line| line.contains("connection.intent.stall_recovered_after_rebind"))
                .count(),
            1,
        );
        assert_eq!(
            report
                .application_log
                .lines()
                .filter(|line| line.contains("connection.intent.recovered"))
                .count(),
            1,
        );
    }
}
