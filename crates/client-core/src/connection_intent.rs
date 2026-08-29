use crate::ConnectOptions;
#[cfg(not(target_os = "android"))]
use nelomai_contracts::Connection;
use nelomai_contracts::{Layer, TicConnectionMode};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
#[cfg(not(target_os = "android"))]
use thiserror::Error;

const RETRY_DELAYS_SECONDS: [u64; 7] = [0, 2, 5, 15, 30, 60, 300];

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IntentGeneration(u64);

impl IntentGeneration {
    pub const fn value(self) -> u64 {
        self.0
    }

    #[cfg(not(target_os = "android"))]
    fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionIntentStatus {
    None,
    Recovering,
    BlockedTerminal,
}

#[cfg(not(target_os = "android"))]
#[derive(Clone, Debug, PartialEq)]
pub enum StartDisposition {
    Connected(Connection),
    Recovering {
        generation: IntentGeneration,
        next_retry_at_unix: Option<i64>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDecision {
    Accept,
    RetrySameOperation,
    RetryNewOperation,
    RetryAfter(u64),
    RetryOnce,
    ReconcileThenRetry,
    ReconcileOnce,
    RestartLocalTunnel,
    Terminal,
    DiscardAndCompensate,
}

impl RecoveryDecision {
    pub const fn policy_name(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::RetrySameOperation => "retry_same_operation",
            Self::RetryNewOperation => "retry_new_operation",
            Self::RetryAfter(_) => "retry_after",
            Self::RetryOnce => "retry_once",
            Self::ReconcileThenRetry => "reconcile_then_retry",
            Self::ReconcileOnce => "reconcile_once",
            Self::RestartLocalTunnel => "local_restart",
            Self::Terminal => "terminal",
            Self::DiscardAndCompensate => "discard_and_compensate",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetrySchedule {
    delays_seconds: [u64; 7],
}

impl RetrySchedule {
    pub const fn delays_seconds(&self) -> [u64; 7] {
        self.delays_seconds
    }

    pub const fn delay_seconds(&self, retry_index: usize) -> u64 {
        if retry_index >= self.delays_seconds.len() {
            self.delays_seconds[self.delays_seconds.len() - 1]
        } else {
            self.delays_seconds[retry_index]
        }
    }
}

impl Default for RetrySchedule {
    fn default() -> Self {
        Self {
            delays_seconds: RETRY_DELAYS_SECONDS,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoveryPolicyContext {
    pub retry_after_seconds: Option<u64>,
    pub service_recovery_attempted: bool,
    pub profile_reissue_attempted: bool,
    pub stalled_reconcile_attempted: bool,
}

pub fn classify_recovery(code: &str, context: RecoveryPolicyContext) -> RecoveryDecision {
    match code {
        "transport_error"
        | "http_5xx"
        | "connection_unavailable"
        | "candidate_unavailable"
        | "configuration_fetch_failed"
        | "connection_release_failed"
        | "probe_results_required"
        | "saved_connection_unavailable"
        | "saved_stray_unavailable"
        | "connection_stall_verification_unavailable"
        | "endpoint_route_lost"
        | "endpoint_route_unavailable"
        | "physical_network_monitor_unavailable"
        | "physical_egress_unavailable"
        | "local_networks_unavailable" => RecoveryDecision::RetrySameOperation,
        "connection_no_longer_active" | "tunnel_handshake_timeout" => {
            RecoveryDecision::RetryNewOperation
        }
        "connection_stall_recycle_rate_limited" => {
            RecoveryDecision::RetryAfter(context.retry_after_seconds.unwrap_or(300).clamp(1, 900))
        }
        "service_unavailable" => {
            if context.service_recovery_attempted {
                RecoveryDecision::Terminal
            } else {
                RecoveryDecision::RetryOnce
            }
        }
        "amneziawg_profile_mismatch"
        | "awg3_profile_apply_failed"
        | "awg3_profile_transform_mismatch" => {
            if context.profile_reissue_attempted {
                RecoveryDecision::Terminal
            } else {
                RecoveryDecision::RetryOnce
            }
        }
        "connection_already_active"
        | "service_timeout"
        | "tunnel_service_timeout"
        | "service_stopping"
        | "android_service_dispatch_unavailable" => RecoveryDecision::ReconcileThenRetry,
        "connection_stall_not_recyclable" => {
            if context.stalled_reconcile_attempted {
                RecoveryDecision::Terminal
            } else {
                RecoveryDecision::ReconcileOnce
            }
        }
        "udp_rebind_failed" | "udp_rebind_timeout" => RecoveryDecision::RestartLocalTunnel,
        _ => RecoveryDecision::Terminal,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTransport {
    AmneziaWg3,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StallRecoveryPlan {
    ReplaceDynamic {
        failure_code: &'static str,
        allow_alternate: bool,
    },
    PreservePeer,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StallTrigger {
    pub options: ConnectOptions,
    pub pinned: bool,
    pub transport: RecoveryTransport,
}

pub fn stall_recovery_plan(
    options: &ConnectOptions,
    pinned: bool,
    transport: RecoveryTransport,
) -> StallRecoveryPlan {
    if !pinned
        && transport == RecoveryTransport::AmneziaWg3
        && (options.layer != Layer::Tic
            || options.tic_connection_mode != TicConnectionMode::Personal)
    {
        StallRecoveryPlan::ReplaceDynamic {
            failure_code: "tunnel_data_plane_stalled",
            allow_alternate: true,
        }
    } else {
        StallRecoveryPlan::PreservePeer
    }
}

pub(crate) fn request_fingerprint_v1(
    options: &ConnectOptions,
    require_measured_selection: bool,
) -> String {
    let canonical = format!(
        concat!(
            "{{\"egress_mode\":\"{}\",",
            "\"kind\":\"start\",",
            "\"layer\":\"{}\",",
            "\"require_measured_selection\":{},",
            "\"route_mode\":\"{}\",",
            "\"tic_connection_mode\":\"{}\"}}"
        ),
        match options.egress_mode {
            nelomai_contracts::EgressMode::Ipv4 => "ipv4",
            nelomai_contracts::EgressMode::PreferIpv6 => "prefer_ipv6",
        },
        match options.layer {
            nelomai_contracts::Layer::Tic => "tic",
            nelomai_contracts::Layer::Stray => "stray",
        },
        require_measured_selection,
        match options.route_mode {
            nelomai_contracts::RouteMode::Standalone => "standalone",
            nelomai_contracts::RouteMode::ViaTak => "via_tak",
        },
        match options.tic_connection_mode {
            nelomai_contracts::TicConnectionMode::Personal => "personal",
            nelomai_contracts::TicConnectionMode::Dynamic => "dynamic",
        },
    );
    let digest = Sha256::digest(canonical.as_bytes());
    let mut fingerprint = String::with_capacity(64);
    for byte in digest {
        let _ = write!(fingerprint, "{byte:02x}");
    }
    fingerprint
}

#[cfg(not(target_os = "android"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct IntentTemplate {
    layer: nelomai_contracts::Layer,
    tic_connection_mode: nelomai_contracts::TicConnectionMode,
    route_mode: nelomai_contracts::RouteMode,
    egress_mode: nelomai_contracts::EgressMode,
    allow_alternate: bool,
}

#[cfg(not(target_os = "android"))]
impl From<ConnectOptions> for IntentTemplate {
    fn from(options: ConnectOptions) -> Self {
        Self {
            layer: options.layer,
            tic_connection_mode: options.tic_connection_mode,
            route_mode: options.route_mode,
            egress_mode: options.egress_mode,
            allow_alternate: options.allow_alternate,
        }
    }
}

#[cfg(not(target_os = "android"))]
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConnectionIntentError {
    #[error("another connection intent is already active")]
    DifferentIntentActive,
    #[error("the previous connection attempt is still completing")]
    AttemptStillActive,
    #[error("connection intent generation is exhausted")]
    GenerationExhausted,
}

#[cfg(not(target_os = "android"))]
#[derive(Debug)]
pub struct ConnectionIntentCoordinator {
    generation: IntentGeneration,
    desired: Option<IntentTemplate>,
    status: ConnectionIntentStatus,
    connected: Option<Connection>,
    attempt_generation: Option<IntentGeneration>,
    retry_index: usize,
    next_retry_at_unix: Option<i64>,
    network_wakeup_pending: bool,
    schedule: RetrySchedule,
    exhausted: bool,
}

#[cfg(not(target_os = "android"))]
impl Default for ConnectionIntentCoordinator {
    fn default() -> Self {
        Self {
            generation: IntentGeneration::default(),
            desired: None,
            status: ConnectionIntentStatus::None,
            connected: None,
            attempt_generation: None,
            retry_index: 0,
            next_retry_at_unix: None,
            network_wakeup_pending: false,
            schedule: RetrySchedule::default(),
            exhausted: false,
        }
    }
}

#[cfg(not(target_os = "android"))]
impl ConnectionIntentCoordinator {
    pub const fn generation(&self) -> IntentGeneration {
        self.generation
    }

    pub const fn status(&self) -> ConnectionIntentStatus {
        self.status
    }

    pub fn start_or_resume(
        &mut self,
        options: ConnectOptions,
        _now_unix: i64,
    ) -> Result<StartDisposition, ConnectionIntentError> {
        let template = IntentTemplate::from(options.normalized_for_layer());
        if let Some(current) = &self.desired {
            if current != &template {
                return Err(ConnectionIntentError::DifferentIntentActive);
            }
            if self.status == ConnectionIntentStatus::BlockedTerminal {
                let Some(next_generation) = self.generation.next() else {
                    self.exhausted = true;
                    return Err(ConnectionIntentError::GenerationExhausted);
                };
                self.generation = next_generation;
                self.status = ConnectionIntentStatus::Recovering;
                self.connected = None;
                self.retry_index = 0;
                self.next_retry_at_unix = None;
                self.network_wakeup_pending = false;
                return Ok(StartDisposition::Recovering {
                    generation: self.generation,
                    next_retry_at_unix: None,
                });
            }
            return Ok(match &self.connected {
                Some(connection) => StartDisposition::Connected(connection.clone()),
                None => StartDisposition::Recovering {
                    generation: self.generation,
                    next_retry_at_unix: self.next_retry_at_unix,
                },
            });
        }
        if self.attempt_generation.is_some() {
            return Err(ConnectionIntentError::AttemptStillActive);
        }
        if self.exhausted {
            return Err(ConnectionIntentError::GenerationExhausted);
        }
        self.generation = self
            .generation
            .next()
            .ok_or(ConnectionIntentError::GenerationExhausted)?;
        self.desired = Some(template);
        self.status = ConnectionIntentStatus::Recovering;
        self.connected = None;
        self.retry_index = 0;
        self.next_retry_at_unix = None;
        self.network_wakeup_pending = false;
        Ok(StartDisposition::Recovering {
            generation: self.generation,
            next_retry_at_unix: None,
        })
    }

    pub fn begin_attempt(&mut self, generation: IntentGeneration) -> bool {
        if generation != self.generation
            || self.desired.is_none()
            || self.attempt_generation.is_some()
        {
            return false;
        }
        self.attempt_generation = Some(generation);
        true
    }

    pub fn handle_stall(
        &mut self,
        trigger: StallTrigger,
    ) -> Result<StallRecoveryPlan, ConnectionIntentError> {
        let options = trigger.options.normalized_for_layer();
        let template = IntentTemplate::from(options.clone());
        if self.desired.as_ref() != Some(&template) {
            return Err(ConnectionIntentError::DifferentIntentActive);
        }
        self.connected = None;
        self.status = ConnectionIntentStatus::Recovering;
        self.retry_index = 0;
        self.next_retry_at_unix = None;
        self.network_wakeup_pending = false;
        Ok(stall_recovery_plan(
            &options,
            trigger.pinned,
            trigger.transport,
        ))
    }

    pub fn accept_result(&mut self, generation: IntentGeneration) -> RecoveryDecision {
        if generation != self.generation
            || self.desired.is_none()
            || self.attempt_generation != Some(generation)
        {
            return RecoveryDecision::DiscardAndCompensate;
        }
        self.attempt_generation = None;
        RecoveryDecision::Accept
    }

    pub fn complete_compensation(&mut self, generation: IntentGeneration) -> bool {
        if self.attempt_generation != Some(generation)
            || (generation == self.generation && self.desired.is_some())
        {
            return false;
        }
        self.attempt_generation = None;
        true
    }

    pub fn mark_connected(
        &mut self,
        generation: IntentGeneration,
        connection: Connection,
    ) -> RecoveryDecision {
        let decision = self.accept_result(generation);
        if decision == RecoveryDecision::Accept {
            self.connected = Some(connection);
            self.status = ConnectionIntentStatus::None;
            self.retry_index = 0;
            self.next_retry_at_unix = None;
            self.network_wakeup_pending = false;
        }
        decision
    }

    pub fn mark_terminal(&mut self, generation: IntentGeneration, armed: bool) -> bool {
        if self.accept_result(generation) != RecoveryDecision::Accept {
            return false;
        }
        self.next_retry_at_unix = None;
        self.network_wakeup_pending = false;
        if armed {
            self.status = ConnectionIntentStatus::BlockedTerminal;
        } else {
            self.status = ConnectionIntentStatus::None;
            self.desired = None;
            self.connected = None;
        }
        true
    }

    pub fn cancel_intent(&mut self, generation: IntentGeneration) -> bool {
        if generation != self.generation || self.desired.is_none() {
            return false;
        }
        match self.generation.next() {
            Some(next) => self.generation = next,
            None => self.exhausted = true,
        }
        self.desired = None;
        self.connected = None;
        self.status = ConnectionIntentStatus::None;
        self.retry_index = 0;
        self.next_retry_at_unix = None;
        self.network_wakeup_pending = false;
        true
    }

    pub fn schedule_retry(&mut self, generation: IntentGeneration, now_unix: i64) -> Option<i64> {
        if generation != self.generation || self.desired.is_none() {
            return None;
        }
        let delay = self.schedule.delay_seconds(self.retry_index);
        self.retry_index = self.retry_index.saturating_add(1);
        let delay = i64::try_from(delay).unwrap_or(i64::MAX);
        let next = now_unix.saturating_add(delay);
        self.next_retry_at_unix = Some(next);
        self.status = ConnectionIntentStatus::Recovering;
        Some(next)
    }

    pub fn wake_for_network_change(&mut self) -> bool {
        if self.desired.is_none()
            || self.status != ConnectionIntentStatus::Recovering
            || self.network_wakeup_pending
        {
            return false;
        }
        self.network_wakeup_pending = true;
        true
    }

    pub fn take_network_wakeup(&mut self) -> bool {
        let pending = std::mem::take(&mut self.network_wakeup_pending);
        if pending {
            self.next_retry_at_unix = None;
            if self.retry_index > 0 {
                self.retry_index = 1;
            }
        }
        pending
    }
}
