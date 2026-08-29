use crate::{
    commands::{CommandError, StartCommandResponse},
    diagnostics::AppDiagnostics,
    NativeApplication,
};
use nelomai_client_application::ApplicationError;
use nelomai_client_core::{
    classify_recovery, ConnectOptions, ConnectionIntentCoordinator, ConnectionIntentStatus,
    CoreApiError, CoreError, CoreState, IntentGeneration, Phase, RecoveryDecision,
    RecoveryPolicyContext, RecoveryTransport, StallRecoveryPlan, StallTrigger,
    StalledDataPlaneRecovery, StalledDataPlaneRecoveryOutcome, StartDisposition,
};
use nelomai_contracts::{Connection, LeaseStatus};
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use tauri::{AppHandle, Emitter};
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
    reconcile_before_attempt: bool,
    repair_before_attempt: bool,
    armed: bool,
    slow_recovery_reported: bool,
    attempt_kind: AttemptKind,
    retry_count: u32,
    owned_lease_id: Option<String>,
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
            reconcile_before_attempt: false,
            repair_before_attempt: false,
            armed: false,
            slow_recovery_reported: false,
            attempt_kind: AttemptKind::Start,
            retry_count: 0,
            owned_lease_id: None,
        }
    }
}

pub(crate) struct DesktopConnectionIntent {
    app: AppHandle,
    application: Arc<NativeApplication>,
    diagnostics: Arc<AppDiagnostics>,
    state: Mutex<RuntimeState>,
    wake: Notify,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeConnectionChangedEvent {
    error: Option<CommandError>,
    action: &'static str,
}

impl DesktopConnectionIntent {
    pub(crate) fn new(
        app: AppHandle,
        application: Arc<NativeApplication>,
        diagnostics: Arc<AppDiagnostics>,
    ) -> Self {
        Self {
            app,
            application,
            diagnostics,
            state: Mutex::new(RuntimeState::default()),
            wake: Notify::new(),
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

    pub(crate) async fn start_or_resume(
        &self,
        options: ConnectOptions,
        now_unix: i64,
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
            .record_named("connection.intent.started", None, None, None);
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
                state.reconcile_before_attempt = false;
                state.repair_before_attempt = false;
                state.armed = false;
                state.slow_recovery_reported = false;
                state.attempt_kind = AttemptKind::Start;
                state.retry_count = 0;
                state.owned_lease_id = None;
            }
            cancelled
        };
        if cancelled {
            self.diagnostics
                .record_named("connection.intent.cancelled", None, None, None);
            self.wake.notify_one();
        }
        cancelled
    }

    pub(crate) async fn wake_for_network_change(&self) -> bool {
        let woke = {
            let mut state = self.state.lock().await;
            let woke = state.coordinator.wake_for_network_change();
            if woke {
                state.next_retry_at_unix = None;
            }
            woke
        };
        if woke {
            self.diagnostics
                .record_named("connection.intent.network_wakeup", None, None, None);
            self.wake.notify_one();
        }
        woke
    }

    pub(crate) async fn handle_stall(&self, lease_id: &str) -> bool {
        let options = {
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
            options
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
                self.diagnostics.record_named(
                    "connection.intent.stall_recovered_after_rebind",
                    Some(lease_id),
                    None,
                    None,
                );
                return true;
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
            self.diagnostics.record_named(
                "connection.intent.stall_recovered_after_local_restart",
                Some(lease_id),
                None,
                None,
            );
            return true;
        }

        let generation = {
            let mut state = self.state.lock().await;
            if state
                .coordinator
                .handle_stall(StallTrigger {
                    options: options.clone(),
                    pinned,
                    transport,
                })
                .is_err()
            {
                return true;
            }
            let generation = state.coordinator.generation();
            if plan == StallRecoveryPlan::PreservePeer {
                state.coordinator.begin_attempt(generation);
                state.coordinator.mark_terminal(generation, true);
                state.next_retry_at_unix = None;
                drop(state);
                self.diagnostics.record_named(
                    "connection.intent.terminal_failure",
                    Some(lease_id),
                    None,
                    Some("connection_stall_not_recyclable"),
                );
                self.emit_change(Some(CommandError::new(
                    "connection_stall_not_recyclable",
                    "Подключение не удалось безопасно заменить автоматически",
                )));
                return true;
            }
            state.attempt_kind = AttemptKind::StallReplacement;
            state.next_retry_at_unix = None;
            consume_immediate_retry_slot(
                &mut state.coordinator,
                generation,
                crate::current_unix_time(),
            );
            generation
        };
        self.diagnostics.record_named(
            "connection.intent.lease_replacement_started",
            Some(lease_id),
            None,
            None,
        );
        let _ = self.run_attempt(generation).await;
        true
    }

    async fn scheduler_loop(self: Arc<Self>) {
        loop {
            let sleep_seconds = {
                let mut state = self.state.lock().await;
                if state.coordinator.take_network_wakeup() {
                    state.next_retry_at_unix = Some(crate::current_unix_time());
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
        let (options, reconcile_before_attempt, repair_before_attempt, attempt_kind) = {
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
            (
                options,
                std::mem::take(&mut state.reconcile_before_attempt),
                std::mem::take(&mut state.repair_before_attempt),
                state.attempt_kind,
            )
        };
        if reconcile_before_attempt {
            let _ = self.application.reconcile_external_tunnel_state().await;
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

    async fn complete_success(
        &self,
        generation: IntentGeneration,
        connection: Connection,
    ) -> Result<StartCommandResponse, CommandError> {
        let (decision, recovered) = {
            let mut state = self.state.lock().await;
            let recovered =
                state.retry_count > 0 || state.attempt_kind == AttemptKind::StallReplacement;
            let decision = state
                .coordinator
                .mark_connected(generation, connection.clone());
            if decision == RecoveryDecision::Accept {
                state.next_retry_at_unix = None;
                state.policy = RecoveryPolicyContext::default();
                state.armed = true;
                state.slow_recovery_reported = false;
                state.attempt_kind = AttemptKind::Start;
                state.retry_count = 0;
                state.owned_lease_id = Some(connection.lease_id.clone());
            }
            (decision, recovered)
        };
        if decision == RecoveryDecision::Accept {
            if recovered {
                self.diagnostics.record_named(
                    "connection.intent.recovered",
                    Some(&connection.lease_id),
                    None,
                    None,
                );
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
        let (decision, next_retry_at_unix, report_slow, retry_count) = {
            let mut state = self.state.lock().await;
            state.policy.retry_after_seconds = retry_after_seconds;
            let decision = classify_recovery(&code, state.policy);
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
                if !armed {
                    state.options = None;
                }
                (decision, None, false, state.retry_count)
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
                state.reconcile_before_attempt = matches!(
                    decision,
                    RecoveryDecision::ReconcileThenRetry | RecoveryDecision::ReconcileOnce
                );
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
                state.retry_count = state.retry_count.saturating_add(1);
                let report_slow = !state.slow_recovery_reported
                    && next.is_some_and(|next| next.saturating_sub(now) >= 300);
                if report_slow {
                    state.slow_recovery_reported = true;
                }
                (decision, next, report_slow, state.retry_count)
            }
        };
        if decision == RecoveryDecision::Terminal {
            self.diagnostics.record_named(
                "connection.intent.terminal_failure",
                None,
                None,
                Some(&code),
            );
            self.emit_change(Some(command_error.clone()));
            return Err(command_error);
        }
        let retry_detail = format!(
            "{code}:attempt={}:delay={}",
            retry_count,
            next_retry_at_unix
                .map(|next| next.saturating_sub(crate::current_unix_time()).max(0))
                .unwrap_or_default()
        );
        self.diagnostics.record_named(
            "connection.intent.retry_scheduled",
            None,
            None,
            Some(&retry_detail),
        );
        if report_slow {
            self.diagnostics.record_named(
                "connection.intent.slow_recovery_notified",
                None,
                None,
                Some(&code),
            );
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
    state.reconcile_before_attempt = false;
    state.repair_before_attempt = false;
    state.slow_recovery_reported = false;
    state.retry_count = 0;
    if !state.armed {
        state.attempt_kind = AttemptKind::Start;
    }
    consume_immediate_retry_slot(&mut state.coordinator, generation, now_unix);
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

fn can_begin_stall_recovery(status: ConnectionIntentStatus, armed: bool) -> bool {
    armed && status == ConnectionIntentStatus::None
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
        can_begin_stall_recovery, connection_matches_core_state, consume_immediate_retry_slot,
        error_retry_after_seconds, recovering_action, stable_error_code, update_policy_context,
        StartRuntimeAction,
    };
    use nelomai_client_application::ApplicationError;
    use nelomai_client_core::{
        classify_recovery, ConnectOptions, ConnectionIntentCoordinator, CoreApiError, CoreError,
        CoreState, Phase, RecoveryDecision, RecoveryPolicyContext, StartDisposition,
    };
    use nelomai_contracts::{
        Connection, EgressMode, Layer, LeaseStatus, RouteMode, TicConnectionMode,
    };

    fn connection(lease_id: &str) -> Connection {
        Connection {
            lease_id: lease_id.to_string(),
            pool_id: Some("pool".to_string()),
            layer: Layer::Stray,
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
}
