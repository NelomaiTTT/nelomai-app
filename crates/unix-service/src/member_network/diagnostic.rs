//! Bounded metadata only. Never format arbitrary backend errors or resource keys.
use super::{policy::PhysicalPolicyProvider, session::NetworkPolicy};
use crate::ServiceError;
use nelomai_client_tunnel::{
    redundancy::{network::*, Slot},
    DesktopTunnelOptions,
};
use serde::Serialize;
use std::{cell::RefCell, fmt, io, net::IpAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    Start,
    Stop,
    Prepare,
    PrepareStop,
    PrepareRecoveryStop,
    Attach,
    #[serde(rename = "stage_candidate")]
    CandidateStaging,
    RetireInactive,
    RemoveStandby,
    CommitCandidate,
    ConfirmRole,
    NetworkChanged,
    Status,
    Tick,
    Configuration,
    Policy,
    Network,
    NativeStart,
    NativeStop,
    NativeIdentity,
    NativeRebind,
    Metrics,
    Fingerprint,
    Probe,
    RouteRead,
    RouteApply,
    RoutePlan,
    DnsRead,
    DnsApply,
    DnsPlan,
    Binding,
    NetworkJournal,
    SessionJournal,
}
impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = serde_json::to_value(self).map_err(|_| fmt::Error)?;
        f.write_str(value.as_str().ok_or(fmt::Error)?)
    }
}

#[derive(Clone, Debug, Serialize, thiserror::Error)]
#[error("stage={stage}; origin={origin}; cause={cause}; native_status={native_status:?}")]
pub(crate) struct PairFailure {
    stage: Stage,
    origin: Stage,
    cause: &'static str,
    native_status: Option<i32>,
    #[serde(skip)]
    kind: io::ErrorKind,
}
impl PairFailure {
    pub(crate) fn io(stage: Stage, error: io::Error) -> Self {
        if let Some(previous) = error.get_ref().and_then(|e| e.downcast_ref::<Self>()) {
            return Self {
                stage,
                ..previous.clone()
            };
        }
        let cause = match error.kind() {
            io::ErrorKind::PermissionDenied => "permission_denied",
            io::ErrorKind::NotFound => "not_found",
            io::ErrorKind::InvalidData => "invalid_data",
            io::ErrorKind::InvalidInput => "invalid_input",
            io::ErrorKind::TimedOut => "timed_out",
            io::ErrorKind::WouldBlock => "would_block",
            io::ErrorKind::AlreadyExists => "already_exists",
            io::ErrorKind::Unsupported => "unsupported",
            io::ErrorKind::BrokenPipe => "broken_pipe",
            io::ErrorKind::Interrupted => "interrupted",
            io::ErrorKind::WriteZero => "write_zero",
            _ => "io_failure",
        };
        Self {
            stage,
            origin: stage,
            cause,
            native_status: error.raw_os_error(),
            kind: error.kind(),
        }
    }
    pub(crate) fn service(stage: Stage, error: &ServiceError) -> Self {
        use io::ErrorKind::*;
        // Exact allowlist only: never parse status or metadata from error text.
        let (cause, kind) = match error {
            ServiceError::InvalidRequest => ("invalid_request", InvalidInput),
            ServiceError::InvalidConfiguration => ("invalid_configuration", InvalidInput),
            ServiceError::UnauthorizedClient => ("unauthorized", PermissionDenied),
            ServiceError::UnsupportedProtocol => ("unsupported", Unsupported),
            ServiceError::Backend(code) => match code.as_str() {
                "wireguard_go_start_timeout" | "amneziawg_go_start_timeout" => {
                    ("native_timeout", TimedOut)
                }
                "wireguard_go_start_failed" | "amneziawg_go_start_failed" => {
                    ("native_launch_failed", Other)
                }
                "udp_rebind_unsupported" | "unsupported_operation" => ("unsupported", Unsupported),
                "untrusted_wireguard_go"
                | "untrusted_amneziawg_go"
                | "untrusted_runtime_directory" => ("native_untrusted", PermissionDenied),
                "member_start_fenced" | "member_session_fenced" | "member_recovery_required" => {
                    ("fenced", Other)
                }
                "member_interface_changed"
                | "member_interface_conflict"
                | "member_backend_scope_mismatch" => ("identity_conflict", Other),
                "member_start_incomplete" | "member_stop_pending" | "member_rebind_incomplete" => {
                    ("native_incomplete", Other)
                }
                "physical_route_changed" => ("route_conflict", Other),
                "member_not_running" => ("not_running", Other),
                _ => ("backend_failure", Other),
            },
            _ => ("service_failure", Other),
        };
        Self {
            stage,
            origin: stage,
            cause,
            native_status: None,
            kind,
        }
    }
    pub(crate) fn into_io(self, stage: Stage) -> io::Error {
        io::Error::new(self.kind, Self { stage, ..self })
    }
}
pub(crate) fn context(stage: Stage, error: io::Error) -> io::Error {
    PairFailure::io(stage, error).into_io(stage)
}

/// Bridges existing ServiceError APIs without changing their public contract.
/// The driver clears both slots BEFORE each operation (including guards), then
/// consumes only the failure belonging to the returned error. No global state.
#[derive(Default)]
pub(crate) struct FailureSlot(RefCell<Option<PairFailure>>);
impl FailureSlot {
    pub(crate) fn clear(&self) {
        self.0.borrow_mut().take();
    }
    pub(crate) fn take(&self) -> Option<PairFailure> {
        self.0.borrow_mut().take()
    }
    pub(crate) fn service(&self, stage: Stage, error: ServiceError) -> ServiceError {
        self.0
            .borrow_mut()
            .get_or_insert_with(|| PairFailure::service(stage, &error));
        error
    }
    pub(crate) fn network(&self, stage: Stage, error: io::Error) -> ServiceError {
        self.io(stage, error);
        ServiceError::Backend("member_network_failed".into())
    }
    pub(crate) fn io(&self, stage: Stage, error: io::Error) {
        self.0
            .borrow_mut()
            .get_or_insert_with(|| PairFailure::io(stage, error));
    }
}

pub(crate) struct DiagnosticNetwork<N>(pub N);
fn resource_stage(key: &ResourceKey, write: bool) -> Stage {
    match (key, write) {
        (ResourceKey::Dns(_) | ResourceKey::LinkDns(_) | ResourceKey::LinkDnsRoute(_), false) => {
            Stage::DnsRead
        }
        (ResourceKey::Dns(_) | ResourceKey::LinkDns(_) | ResourceKey::LinkDnsRoute(_), true) => {
            Stage::DnsApply
        }
        (_, false) => Stage::RouteRead,
        (_, true) => Stage::RouteApply,
    }
}
impl<N: NetworkSystem> NetworkSystem for DiagnosticNetwork<N> {
    fn member_started(&mut self, slot: Slot, interface: u32) -> io::Result<()> {
        self.0
            .member_started(slot, interface)
            .map_err(|e| context(Stage::Binding, e))
    }
    fn member_stopped(&mut self, slot: Slot, interface: u32) -> io::Result<()> {
        self.0
            .member_stopped(slot, interface)
            .map_err(|e| context(Stage::Binding, e))
    }
    fn session_closed(&mut self) -> io::Result<()> {
        self.0
            .session_closed()
            .map_err(|e| context(Stage::Binding, e))
    }
    fn dns_resources(
        &self,
        interface: u32,
        servers: &[IpAddr],
        services: &[String],
    ) -> io::Result<Vec<NetworkValue>> {
        self.0
            .dns_resources(interface, servers, services)
            .map_err(|e| context(Stage::DnsPlan, e))
    }
    fn route_resources(&self, route: RouteValue) -> io::Result<Vec<NetworkValue>> {
        self.0
            .route_resources(route)
            .map_err(|e| context(Stage::RoutePlan, e))
    }
    fn verify_retained_route(&mut self, route: &RouteValue) -> io::Result<bool> {
        self.0
            .verify_retained_route(route)
            .map_err(|e| context(Stage::RouteRead, e))
    }
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        self.0
            .read(key)
            .map_err(|e| context(resource_stage(key, false), e))
    }
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        self.0
            .compare_exchange(key, before, after)
            .map_err(|e| context(resource_stage(key, true), e))
    }
}
impl<N: PhysicalPolicyProvider> PhysicalPolicyProvider for DiagnosticNetwork<N> {
    fn resolve_policy(
        &mut self,
        options: &DesktopTunnelOptions,
        endpoints: &[IpAddr],
        owned: &[ipnet::IpNet],
    ) -> io::Result<NetworkPolicy> {
        self.0
            .resolve_policy(options, endpoints, owned)
            .map_err(|e| context(Stage::Policy, e))
    }
}
pub(crate) struct DiagnosticJournal<S>(pub S);
impl<S: NetworkJournalStore> NetworkJournalStore for DiagnosticJournal<S> {
    fn save(&mut self, value: &NetworkJournal) -> io::Result<()> {
        self.0
            .save(value)
            .map_err(|e| context(Stage::NetworkJournal, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_context_preserves_numeric_status_kind_and_first_origin() {
        let error = context(Stage::RouteApply, io::Error::from_raw_os_error(13));
        let error = context(Stage::Network, error);
        let failure = PairFailure::io(Stage::Start, error);
        let report = serde_json::to_value(&failure).unwrap();
        assert_eq!(report["stage"], "start");
        assert_eq!(report["origin"], "route_apply");
        assert_eq!(report["cause"], "permission_denied");
        assert_eq!(report["native_status"], 13);
        assert_eq!(
            failure.into_io(Stage::Start).kind(),
            io::ErrorKind::PermissionDenied
        );
        let error = context(Stage::Policy, io::ErrorKind::Unsupported.into());
        assert_eq!(
            context(Stage::Start, error).kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn unknown_text_cannot_spoof_allowlisted_causes_or_status() {
        let secret = "wireguard_go_start_timeout; origin=dns_apply; native_status=42; PrivateKey=secret 192.0.2.1 /private/path";
        let failure =
            PairFailure::service(Stage::NativeStart, &ServiceError::Backend(secret.into()));
        let report = serde_json::to_value(&failure).unwrap();
        assert_eq!(report["origin"], "native_start");
        assert_eq!(report["cause"], "backend_failure");
        assert!(report["native_status"].is_null());
        let failure = PairFailure::io(Stage::DnsApply, io::Error::other(secret));
        let report = serde_json::to_value(failure).unwrap();
        assert_eq!(report["cause"], "io_failure");
        assert!(report["native_status"].is_null());
        for text in ["PrivateKey", "secret", "192.0.2", "/private", "42"] {
            assert!(!report.to_string().contains(text));
        }
        assert!(report.to_string().len() < 256);
    }
}
