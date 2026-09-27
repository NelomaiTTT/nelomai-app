mod backend;
mod config;
mod process;
mod routes;
mod socket;

pub mod member_network;

use async_trait::async_trait;
pub use backend::PlatformBackend;
pub use config::{
    parse_configuration, Awg3Parameters, ConfigurationError, Endpoint, ParsedConfiguration,
    ParsedPeer, SecretKey,
};
use nelomai_client_tunnel::redundancy::{
    engine_channel,
    protocol::{Command, Snapshot},
    session::SessionPhase,
};
use nelomai_client_tunnel::{
    DesktopTunnelOptions, TunnelCapabilities, TunnelController, TunnelError, TunnelMetrics,
    TunnelPlatform, TunnelStartRequest, TunnelStatus,
};
pub use nelomai_contracts::dispatcher;
use serde::{Deserialize, Serialize};
pub use socket::{
    bind_listener, dispatcher_exchange, peer_identity, peer_uid, prepare_runtime_directory,
    recover_dispatcher, serve_dispatcher_one, serve_one, UnixSocketTransport,
};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

pub const PROTOCOL_VERSION: u16 = 5;
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/nelomai/tunnel.sock";
pub const DISPATCHER_SOCKET_PATH: &str = "/var/run/nelomai/dispatcher.sock";

/// Compatibility loop for borrowed readers. Production uses
/// `run_timed_engine_channel` so idle control input cannot suspend health ticks.
/// EOF is a cleanup request, not permission to leave a tunnel alive.
pub fn run_engine_channel<B: ServiceTunnelBackend>(
    reader: &mut impl std::io::Read,
    writer: &mut impl std::io::Write,
    handler: &mut TunnelRequestHandler<B>,
) -> std::io::Result<()> {
    use nelomai_contracts::dispatcher as d;
    loop {
        let frame = match d::read_frame(reader, MAX_FRAME_SIZE) {
            Ok(frame) => frame,
            Err(error) => {
                let cleanup = handler.shutdown().map_err(std::io::Error::other);
                return if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    cleanup
                } else {
                    Err(error)
                };
            }
        };
        let control: serde_json::Value =
            serde_json::from_slice(d::frame_body(&frame, MAX_FRAME_SIZE)?)
                .unwrap_or(serde_json::Value::Null);
        let output = match control
            .get("dispatcher_control")
            .and_then(|value| value.as_str())
        {
            Some("ready") => d::encode_frame(&serde_json::json!({"engine_ready":true}))?,
            Some("stop") => {
                // Dispatcher process teardown has explicit force-shutdown
                // authority; an ordinary product Stop does not.
                let stopped = handler.shutdown().is_ok();
                d::encode_frame(&serde_json::json!({"engine_stopped": stopped}))?
            }
            _ => {
                let response = decode_request(&frame)
                    .map(|request| handler.handle(request))
                    .unwrap_or_else(|error| Response::failure(error.code()));
                encode_response(&response).map_err(|_| d::blocked())?
            }
        };
        writer.write_all(&output)?;
        writer.flush()?;
    }
}

/// Run the existing engine process with a single owned control-input reader.
/// The caller must exit the process after return: the shared channel's detached
/// reader may still be blocked on its process-owned pipe. This is Unix-only
/// integration; Windows primitive replies require separate single-reader routing.
pub fn run_timed_engine_channel<B: ServiceTunnelBackend, R: std::io::Read + Send + 'static>(
    reader: R,
    writer: &mut impl std::io::Write,
    handler: &mut TunnelRequestHandler<B>,
) -> std::io::Result<()> {
    engine_channel::run_engine_channel(reader, writer, handler)
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceTunnelState {
    #[default]
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub protocol_version: u16,
    pub ok: bool,
    pub state: Option<ServiceTunnelState>,
    pub service_version: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub desktop_redundancy_v1: bool,
    #[serde(default)]
    pub physical_network_fingerprint: Option<String>,
    #[serde(default)]
    pub metrics: Option<TunnelMetrics>,
    #[serde(default)]
    pub diagnostics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redundancy: Option<Snapshot>,
    pub error_code: Option<String>,
}

impl Response {
    pub fn success(state: Option<ServiceTunnelState>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            ok: true,
            state,
            service_version: None,
            desktop_redundancy_v1: false,
            physical_network_fingerprint: None,
            metrics: None,
            diagnostics: None,
            redundancy: None,
            error_code: None,
        }
    }

    pub fn failure(error_code: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            ok: false,
            state: None,
            service_version: None,
            desktop_redundancy_v1: false,
            physical_network_fingerprint: None,
            metrics: None,
            diagnostics: None,
            redundancy: None,
            error_code: Some(error_code.into()),
        }
    }
}

pub enum Request {
    Redundant {
        protocol_version: u16,
        request: Command,
    },
    Start {
        protocol_version: u16,
        configuration: Zeroizing<String>,
        options: DesktopTunnelOptions,
    },
    Stop {
        protocol_version: u16,
    },
    Status {
        protocol_version: u16,
    },
    Version {
        protocol_version: u16,
    },
    PhysicalNetworkFingerprint {
        protocol_version: u16,
    },
    Metrics {
        protocol_version: u16,
        probe: bool,
    },
    Diagnostics {
        protocol_version: u16,
    },
    RebindUdp {
        protocol_version: u16,
    },
}

impl Request {
    pub fn start(configuration: String) -> Self {
        Self::start_with_options(configuration, DesktopTunnelOptions::default())
    }

    pub fn start_with_options(configuration: String, options: DesktopTunnelOptions) -> Self {
        Self::Start {
            protocol_version: PROTOCOL_VERSION,
            configuration: Zeroizing::new(configuration),
            options,
        }
    }

    pub fn stop() -> Self {
        Self::Stop {
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn status() -> Self {
        Self::Status {
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn version() -> Self {
        Self::Version {
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn physical_network_fingerprint() -> Self {
        Self::PhysicalNetworkFingerprint {
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn metrics(probe: bool) -> Self {
        Self::Metrics {
            protocol_version: PROTOCOL_VERSION,
            probe,
        }
    }

    pub fn diagnostics() -> Self {
        Self::Diagnostics {
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn rebind_udp() -> Self {
        Self::RebindUdp {
            protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Redundant {
                protocol_version, ..
            } => *protocol_version,
            Self::Start {
                protocol_version, ..
            }
            | Self::Stop { protocol_version }
            | Self::Status { protocol_version }
            | Self::Version { protocol_version }
            | Self::PhysicalNetworkFingerprint { protocol_version }
            | Self::Diagnostics { protocol_version }
            | Self::RebindUdp { protocol_version }
            | Self::Metrics {
                protocol_version, ..
            } => *protocol_version,
        }
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redundant {
                protocol_version, ..
            } => formatter
                .debug_struct("Redundant")
                .field("protocol_version", protocol_version)
                .field("request", &"<redacted>")
                .finish(),
            Self::Start {
                protocol_version,
                options,
                ..
            } => formatter
                .debug_struct("Start")
                .field("protocol_version", protocol_version)
                .field("configuration", &"<redacted>")
                .field("options", options)
                .finish(),
            Self::Stop { protocol_version } => formatter
                .debug_struct("Stop")
                .field("protocol_version", protocol_version)
                .finish(),
            Self::Status { protocol_version } => formatter
                .debug_struct("Status")
                .field("protocol_version", protocol_version)
                .finish(),
            Self::Version { protocol_version } => formatter
                .debug_struct("Version")
                .field("protocol_version", protocol_version)
                .finish(),
            Self::PhysicalNetworkFingerprint { protocol_version } => formatter
                .debug_struct("PhysicalNetworkFingerprint")
                .field("protocol_version", protocol_version)
                .finish(),
            Self::Metrics {
                protocol_version,
                probe,
            } => formatter
                .debug_struct("Metrics")
                .field("protocol_version", protocol_version)
                .field("probe", probe)
                .finish(),
            Self::Diagnostics { protocol_version } => formatter
                .debug_struct("Diagnostics")
                .field("protocol_version", protocol_version)
                .finish(),
            Self::RebindUdp { protocol_version } => formatter
                .debug_struct("RebindUdp")
                .field("protocol_version", protocol_version)
                .finish(),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum RequestRef<'a> {
    Redundant {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
        request: &'a Command,
    },
    Start {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
        configuration: &'a str,
        options: &'a DesktopTunnelOptions,
    },
    Stop {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
    Status {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
    Version {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
    PhysicalNetworkFingerprint {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
    Metrics {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
        probe: bool,
    },
    Diagnostics {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
    RebindUdp {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
}

impl Serialize for Request {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Redundant {
                protocol_version,
                request,
            } => RequestRef::Redundant {
                protocol_version: *protocol_version,
                request,
            },
            Self::Start {
                protocol_version,
                configuration,
                options,
            } => RequestRef::Start {
                protocol_version: *protocol_version,
                configuration,
                options,
            },
            Self::Stop { protocol_version } => RequestRef::Stop {
                protocol_version: *protocol_version,
            },
            Self::Status { protocol_version } => RequestRef::Status {
                protocol_version: *protocol_version,
            },
            Self::Version { protocol_version } => RequestRef::Version {
                protocol_version: *protocol_version,
            },
            Self::PhysicalNetworkFingerprint { protocol_version } => {
                RequestRef::PhysicalNetworkFingerprint {
                    protocol_version: *protocol_version,
                }
            }
            Self::Metrics {
                protocol_version,
                probe,
            } => RequestRef::Metrics {
                protocol_version: *protocol_version,
                probe: *probe,
            },
            Self::Diagnostics { protocol_version } => RequestRef::Diagnostics {
                protocol_version: *protocol_version,
            },
            Self::RebindUdp { protocol_version } => RequestRef::RebindUdp {
                protocol_version: *protocol_version,
            },
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum RequestOwned {
    Redundant {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
        request: Command,
    },
    Start {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
        configuration: String,
        #[serde(default)]
        options: DesktopTunnelOptions,
    },
    Stop {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
    Status {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
    Version {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
    PhysicalNetworkFingerprint {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
    Metrics {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
        probe: bool,
    },
    Diagnostics {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
    RebindUdp {
        #[serde(rename = "protocolVersion")]
        protocol_version: u16,
    },
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match RequestOwned::deserialize(deserializer)? {
            RequestOwned::Redundant {
                protocol_version,
                request,
            } => Self::Redundant {
                protocol_version,
                request,
            },
            RequestOwned::Start {
                protocol_version,
                configuration,
                options,
            } => Self::Start {
                protocol_version,
                configuration: Zeroizing::new(configuration),
                options,
            },
            RequestOwned::Stop { protocol_version } => Self::Stop { protocol_version },
            RequestOwned::Status { protocol_version } => Self::Status { protocol_version },
            RequestOwned::Version { protocol_version } => Self::Version { protocol_version },
            RequestOwned::PhysicalNetworkFingerprint { protocol_version } => {
                Self::PhysicalNetworkFingerprint { protocol_version }
            }
            RequestOwned::Metrics {
                protocol_version,
                probe,
            } => Self::Metrics {
                protocol_version,
                probe,
            },
            RequestOwned::Diagnostics { protocol_version } => {
                Self::Diagnostics { protocol_version }
            }
            RequestOwned::RebindUdp { protocol_version } => Self::RebindUdp { protocol_version },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub uid: u32,
    pub process_path: std::path::PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPolicy {
    pub owner_uid: u32,
    pub installed_client_path: std::path::PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ServiceError {
    #[error("IPC frame exceeds the configured limit")]
    FrameTooLarge,
    #[error("IPC frame is truncated")]
    TruncatedFrame,
    #[error("IPC request is invalid")]
    InvalidRequest,
    #[error("IPC client is not authorized")]
    UnauthorizedClient,
    #[error("service protocol version is unsupported")]
    UnsupportedProtocol,
    #[error("WireGuard configuration is invalid")]
    InvalidConfiguration,
    #[error("tunnel helper is unavailable: {0}")]
    Backend(String),
}

impl ServiceError {
    pub fn code(&self) -> &str {
        match self {
            Self::FrameTooLarge => "frame_too_large",
            Self::TruncatedFrame => "truncated_frame",
            Self::InvalidRequest => "invalid_request",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::Backend(code) => stable_route_error_code(code).unwrap_or("service_unavailable"),
        }
    }
}

fn stable_route_error_code(code: &str) -> Option<&'static str> {
    Some(match code {
        "route_plan_too_large" => "route_plan_too_large",
        "route_conflict" => "route_conflict",
        "route_state_too_large" => "route_state_too_large",
        "route_state_invalid" => "route_state_invalid",
        "route_state_read_failed" => "route_state_read_failed",
        "route_state_write_failed" => "route_state_write_failed",
        "route_state_serialize_failed" => "route_state_serialize_failed",
        "route_state_activate_failed" => "route_state_activate_failed",
        "route_state_remove_failed" => "route_state_remove_failed",
        "route_add_failed" => "route_add_failed",
        "interface_up_failed" => "interface_up_failed",
        "route_del_failed" => "route_del_failed",
        "route_delete_failed" => "route_delete_failed",
        "route_command_failed" => "route_command_failed",
        "route_command_unavailable" => "route_command_unavailable",
        "route_table_unavailable" => "route_table_unavailable",
        "ip_command_unavailable" => "ip_command_unavailable",
        "physical_egress_unavailable" => "physical_egress_unavailable",
        "local_networks_unavailable" => "local_networks_unavailable",
        "endpoint_route_unavailable" => "endpoint_route_unavailable",
        "endpoint_route_lost" => "endpoint_route_lost",
        "amneziawg_uapi_unavailable" => "amneziawg_uapi_unavailable",
        "amneziawg_configuration_failed" => "amneziawg_configuration_failed",
        "amneziawg_profile_mismatch" => "amneziawg_profile_mismatch",
        "amneziawg_interface_already_exists" => "amneziawg_interface_already_exists",
        "amneziawg_go_start_failed" => "amneziawg_go_start_failed",
        "amneziawg_go_start_timeout" => "amneziawg_go_start_timeout",
        "untrusted_amneziawg_go" => "untrusted_amneziawg_go",
        "wireguard_go_start_failed" => "wireguard_go_start_failed",
        "wireguard_go_start_timeout" => "wireguard_go_start_timeout",
        "untrusted_wireguard_go" => "untrusted_wireguard_go",
        "untrusted_runtime_directory" => "untrusted_runtime_directory",
        "network_configuration_failed" => "network_configuration_failed",
        "invalid_interface_name" => "invalid_interface_name",
        "tunnel_not_running" => "tunnel_not_running",
        "userspace_log_unavailable" => "userspace_log_unavailable",
        "multiple_tunnel_interfaces_detected" => "multiple_tunnel_interfaces_detected",
        "udp_rebind_failed" => "udp_rebind_failed",
        "udp_rebind_unsupported" => "udp_rebind_unsupported",
        _ => return None,
    })
}

pub fn authorize_peer(
    policy: &ClientPolicy,
    identity: &ClientIdentity,
) -> Result<(), ServiceError> {
    if policy.owner_uid == identity.uid && policy.installed_client_path == identity.process_path {
        Ok(())
    } else {
        Err(ServiceError::UnauthorizedClient)
    }
}

pub trait ServiceTunnelBackend {
    fn supports_redundancy(&self) -> bool {
        false
    }
    fn current_redundancy_snapshot(&self) -> Option<Snapshot> {
        None
    }
    /// Additive protocol support does not enable native redundancy by default.
    /// Implementations must check the command against their actual runtime and
    /// current session ownership before any mutation.
    fn redundant(&mut self, _request: Command) -> Result<Snapshot, ServiceError> {
        Err(ServiceError::Backend("redundancy_unsupported".into()))
    }
    fn tick(&mut self, _now_ms: u64) -> Result<(), ServiceError> {
        Ok(())
    }
    /// Dispatcher process teardown only. Ordinary unscoped Stop continues to
    /// use stop(), allowing a composite backend to fence it independently.
    fn shutdown(&mut self) -> Result<(), ServiceError> {
        if self.stop()? == ServiceTunnelState::Stopped {
            Ok(())
        } else {
            Err(ServiceError::Backend("shutdown_incomplete".into()))
        }
    }
    /// Present only when a native adapter has verified durable session ownership.
    fn member_recovery_scope(&self) -> Option<nelomai_client_tunnel::redundancy::SessionScope> {
        None
    }
    fn member_cleanup_pending(&self) -> bool {
        false
    }
    fn member_slot(&self) -> Option<dispatcher::TunnelSlot> {
        None
    }
    /// Only member-mode backends expose a verified native index. Ordinary
    /// backends and older/fake implementations do not gain this capability.
    fn member_interface_index(&self) -> Result<u32, ServiceError> {
        Err(ServiceError::Backend("member_interface_unavailable".into()))
    }
    fn member_data_counters(&self) -> Result<member_network::counters::DataCounters, ServiceError> {
        let index = self.member_interface_index()?;
        member_network::counters::read_owned(
            index,
            || self.member_interface_index().map_err(std::io::Error::other),
            member_network::counters::native,
        )
        .map_err(|_| ServiceError::Backend("member_counters_unavailable".into()))
    }
    fn start(
        &mut self,
        configuration: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError>;
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError>;
    fn status(&self) -> Result<ServiceTunnelState, ServiceError>;
    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        Err(ServiceError::Backend(
            "physical_network_fingerprint_unavailable".to_string(),
        ))
    }
    fn metrics(&self, _probe: bool) -> Result<TunnelMetrics, ServiceError> {
        Err(ServiceError::Backend("metrics_unavailable".to_string()))
    }
    fn diagnostics(&self) -> Result<String, ServiceError> {
        Err(ServiceError::Backend("diagnostics_unavailable".to_string()))
    }
    fn rebind_udp(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        Err(ServiceError::Backend("udp_rebind_unsupported".to_string()))
    }
}

pub struct TunnelRequestHandler<B> {
    backend: B,
    service_version: String,
    shutdown_requested: bool,
    shutdown_complete: bool,
}

impl<B: ServiceTunnelBackend> TunnelRequestHandler<B> {
    pub fn new(backend: B, service_version: impl Into<String>) -> Self {
        Self {
            backend,
            service_version: service_version.into(),
            shutdown_requested: false,
            shutdown_complete: false,
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn tick(&mut self, now_ms: u64) -> Result<(), ServiceError> {
        if self.shutdown_requested {
            return Ok(());
        }
        self.backend.tick(now_ms)
    }

    pub fn shutdown(&mut self) -> Result<(), ServiceError> {
        self.shutdown_requested = true;
        if self.shutdown_complete {
            return Ok(());
        }
        self.backend.shutdown()?;
        self.shutdown_complete = true;
        Ok(())
    }

    pub fn handle(&mut self, request: Request) -> Response {
        if self.shutdown_requested {
            return Response::failure("engine_stopping");
        }
        if request.protocol_version() != PROTOCOL_VERSION {
            return Response::failure(ServiceError::UnsupportedProtocol.code());
        }

        let result = match request {
            Request::Redundant { request, .. } => {
                // Validate the wire structure using its declared runtime. This
                // is not runtime authorization: only the native owner knows
                // the installed runtime and can compare it with this scope.
                request
                    .validate(request.scope().runtime)
                    .map_err(|_| ServiceError::InvalidRequest)
                    .and_then(|_| self.backend.redundant(request))
                    .map(|snapshot| {
                        let state = if snapshot.cleanup_pending {
                            ServiceTunnelState::Stopping
                        } else {
                            match snapshot.session.phase {
                                SessionPhase::Starting => ServiceTunnelState::Starting,
                                SessionPhase::Running if snapshot.primary_ready => {
                                    ServiceTunnelState::Running
                                }
                                SessionPhase::Running => ServiceTunnelState::Starting,
                                SessionPhase::Stopping => ServiceTunnelState::Stopping,
                                SessionPhase::Stopped => ServiceTunnelState::Stopped,
                            }
                        };
                        let mut response = Response::success(Some(state));
                        response.redundancy = Some(snapshot);
                        response
                    })
            }
            Request::Start {
                configuration,
                options,
                ..
            } => options
                .validate()
                .map_err(|_| ServiceError::InvalidRequest)
                .and_then(|_| {
                    parse_configuration(&configuration)
                        .map_err(|_| ServiceError::InvalidConfiguration)
                })
                .and_then(|configuration| self.backend.start(&configuration, &options))
                .map(|state| Response::success(Some(state))),
            Request::Stop { .. } => self
                .backend
                .stop()
                .map(|state| Response::success(Some(state))),
            Request::Status { .. } => self.backend.status().map(|state| {
                let mut response = Response::success(Some(state));
                response.redundancy = self.backend.current_redundancy_snapshot();
                response
            }),
            Request::Version { .. } => {
                let mut response = Response::success(None);
                response.service_version = Some(self.service_version.clone());
                response.desktop_redundancy_v1 = self.backend.supports_redundancy();
                Ok(response)
            }
            Request::PhysicalNetworkFingerprint { .. } => self
                .backend
                .physical_network_fingerprint()
                .map(|fingerprint| {
                    let mut response = Response::success(None);
                    response.physical_network_fingerprint = Some(fingerprint);
                    response
                }),
            Request::Metrics { probe, .. } => self.backend.metrics(probe).map(|metrics| {
                let mut response = Response::success(None);
                response.metrics = Some(metrics);
                response
            }),
            Request::Diagnostics { .. } => self.backend.diagnostics().map(|diagnostics| {
                let mut response = Response::success(None);
                response.diagnostics = Some(diagnostics);
                response
            }),
            Request::RebindUdp { .. } => self
                .backend
                .rebind_udp()
                .map(|state| Response::success(Some(state))),
        };

        result.unwrap_or_else(|error| Response::failure(error.code()))
    }
}

impl<B: ServiceTunnelBackend> engine_channel::Handler for TunnelRequestHandler<B> {
    fn handle(&mut self, frame: &[u8]) -> std::io::Result<Vec<u8>> {
        let body = dispatcher::frame_body(frame, MAX_FRAME_SIZE)?;
        let control = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|value| value.get("dispatcher_control")?.as_str().map(str::to_owned));

        // The dispatcher expects this explicit acknowledgement before removing
        // its ownership marker/closing the child. Failed cleanup may be retried;
        // neither outcome authorizes another Start in this process.
        if control.as_deref() == Some("stop") {
            let stopped = self.shutdown().is_ok();
            return dispatcher::encode_frame(&serde_json::json!({"engine_stopped": stopped}));
        }
        if self.shutdown_requested {
            return encode_response(&Response::failure("engine_stopping"))
                .map_err(engine_service_error);
        }
        if control.as_deref() == Some("ready") {
            return dispatcher::encode_frame(&serde_json::json!({"engine_ready": true}));
        }

        let response = match decode_request(frame) {
            Ok(request) => self.handle(request),
            Err(error) => {
                // Preserve the private protocol's bounded failure response, but
                // retire native ownership before sending it. Never surface a
                // serde error (which may contain configuration/input details).
                if self.shutdown().is_err() {
                    return Err(engine_service_error(error));
                }
                Response::failure(error.code())
            }
        };
        encode_response(&response).map_err(engine_service_error)
    }

    fn tick(&mut self, now_ms: u64) -> std::io::Result<()> {
        TunnelRequestHandler::tick(self, now_ms).map_err(engine_service_error)
    }

    fn shutdown(&mut self) -> std::io::Result<()> {
        TunnelRequestHandler::shutdown(self).map_err(engine_service_error)
    }
}

fn engine_service_error(error: ServiceError) -> std::io::Error {
    std::io::Error::other(error.code().to_owned())
}

#[async_trait]
pub trait ServiceTransport: Send + Sync {
    async fn exchange(&self, request: Request) -> Result<Response, ServiceError>;
}

pub struct UnixTunnelController<T> {
    transport: T,
}

impl<T> UnixTunnelController<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: ServiceTransport> UnixTunnelController<T> {
    /// Always ask the authenticated helper at command time. A GUI-cached scope
    /// is not authority to stop/rebind a possibly replaced native session.
    async fn current_redundancy_snapshot(&self) -> Result<Option<Snapshot>, TunnelError> {
        let response = self
            .transport
            .exchange(Request::status())
            .await
            .map_err(to_tunnel_error)?;
        validate_response(&response)?;
        if response.state.is_none() {
            return Err(TunnelError::Backend("missing_tunnel_service_state".into()));
        }
        Ok(response.redundancy)
    }

    pub async fn service_version(&self) -> Result<String, TunnelError> {
        let response = self
            .transport
            .exchange(Request::version())
            .await
            .map_err(to_tunnel_error)?;
        validate_response(&response)?;
        response
            .service_version
            .ok_or_else(|| TunnelError::Backend("missing_service_version".to_string()))
    }

    pub async fn diagnostics(&self) -> Result<String, TunnelError> {
        let response = self
            .transport
            .exchange(Request::diagnostics())
            .await
            .map_err(to_tunnel_error)?;
        validate_response(&response)?;
        response
            .diagnostics
            .ok_or_else(|| TunnelError::Backend("missing_service_diagnostics".to_string()))
    }
}

#[async_trait]
impl<T: ServiceTransport> TunnelController for UnixTunnelController<T> {
    async fn desktop_redundancy_absent(&self) -> Result<bool, TunnelError> {
        let response = self
            .transport
            .exchange(Request::status())
            .await
            .map_err(to_tunnel_error)?;
        validate_response(&response)?;
        let state = response
            .state
            .ok_or_else(|| TunnelError::Backend("missing_tunnel_service_state".into()))?;
        Ok(state == ServiceTunnelState::Stopped && response.redundancy.is_none())
    }

    async fn desktop_redundancy_supported(&self) -> Result<bool, TunnelError> {
        let response = self
            .transport
            .exchange(Request::version())
            .await
            .map_err(to_tunnel_error)?;
        validate_response(&response)?;
        Ok(response.desktop_redundancy_v1)
    }

    async fn desktop_redundancy_command(&self, command: Command) -> Result<Snapshot, TunnelError> {
        command
            .validate(command.scope().runtime)
            .map_err(|_| TunnelError::Backend("invalid_redundant_command".into()))?;
        let scope = command.scope().clone();
        let response = self
            .transport
            .exchange(Request::Redundant {
                protocol_version: PROTOCOL_VERSION,
                request: command,
            })
            .await
            .map_err(to_tunnel_error)?;
        validate_response(&response)?;
        let snapshot = response
            .redundancy
            .ok_or_else(|| TunnelError::Backend("missing_redundancy_snapshot".into()))?;
        if snapshot.session.scope != scope {
            return Err(TunnelError::Backend("redundancy_scope_mismatch".into()));
        }
        Ok(snapshot)
    }

    async fn start(&self, mut request: TunnelStartRequest) -> Result<(), TunnelError> {
        request
            .options
            .validate()
            .map_err(|error| TunnelError::InvalidOptions {
                code: error.stable_code(),
            })?;
        request
            .configuration
            .override_dns(&request.options.dns_servers)
            .map_err(|error| TunnelError::Backend(error.to_string()))?;
        let response = self
            .transport
            .exchange(Request::start_with_options(
                request.configuration.expose().to_string(),
                DesktopTunnelOptions::from_tunnel_options(&request.options),
            ))
            .await
            .map_err(to_tunnel_error)?;
        require_state(response, ServiceTunnelState::Running)
    }

    async fn stop(&self) -> Result<(), TunnelError> {
        if let Some(snapshot) = self.current_redundancy_snapshot().await? {
            let stopped = self
                .desktop_redundancy_command(Command::Stop {
                    scope: snapshot.session.scope,
                })
                .await?;
            return if stopped.session.phase == SessionPhase::Stopped && !stopped.cleanup_pending {
                Ok(())
            } else {
                Err(TunnelError::Backend("redundancy_cleanup_pending".into()))
            };
        }
        let response = self
            .transport
            .exchange(Request::stop())
            .await
            .map_err(to_tunnel_error)?;
        require_state(response, ServiceTunnelState::Stopped)
    }

    async fn stop_if_unowned(&self) -> Result<(), TunnelError> {
        // Unlike an explicit user/auth Stop, stale single-session cleanup must
        // not acquire the currently running pair's scope from a fresh Status.
        let response = self
            .transport
            .exchange(Request::stop())
            .await
            .map_err(to_tunnel_error)?;
        require_state(response, ServiceTunnelState::Stopped)
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        let response = self
            .transport
            .exchange(Request::status())
            .await
            .map_err(to_tunnel_error)?;
        validate_response(&response)?;
        match response.state {
            Some(ServiceTunnelState::Stopped) => Ok(TunnelStatus::Stopped),
            Some(ServiceTunnelState::Starting) => Ok(TunnelStatus::Starting),
            Some(ServiceTunnelState::Running) => Ok(TunnelStatus::Running),
            Some(ServiceTunnelState::Stopping) => Ok(TunnelStatus::Stopping),
            Some(ServiceTunnelState::Failed) => Ok(TunnelStatus::Failed),
            None => Err(TunnelError::Backend(
                "missing_tunnel_service_state".to_string(),
            )),
        }
    }

    async fn physical_network_fingerprint(&self) -> Result<Option<String>, TunnelError> {
        let response = self
            .transport
            .exchange(Request::physical_network_fingerprint())
            .await
            .map_err(to_tunnel_error)?;
        validate_response(&response)?;
        let fingerprint = response.physical_network_fingerprint.ok_or_else(|| {
            TunnelError::Backend("missing_physical_network_fingerprint".to_string())
        })?;
        if valid_fingerprint(&fingerprint) {
            Ok(Some(fingerprint))
        } else {
            Err(TunnelError::Backend(
                "invalid_physical_network_fingerprint".to_string(),
            ))
        }
    }

    async fn metrics(&self, probe: bool) -> Result<Option<TunnelMetrics>, TunnelError> {
        let response = self
            .transport
            .exchange(Request::metrics(probe))
            .await
            .map_err(to_tunnel_error)?;
        validate_response(&response)?;
        response
            .metrics
            .map(Some)
            .ok_or_else(|| TunnelError::Backend("missing_tunnel_metrics".to_string()))
    }

    async fn rebind_udp(&self) -> Result<bool, TunnelError> {
        if let Some(snapshot) = self.current_redundancy_snapshot().await? {
            let rebound = self
                .desktop_redundancy_command(Command::NetworkChanged {
                    scope: snapshot.session.scope,
                })
                .await?;
            return if rebound.session.phase == SessionPhase::Running && !rebound.cleanup_pending {
                Ok(true)
            } else {
                Err(TunnelError::Backend("redundancy_rebind_incomplete".into()))
            };
        }
        let response = self
            .transport
            .exchange(Request::rebind_udp())
            .await
            .map_err(to_tunnel_error)?;
        require_state(response, ServiceTunnelState::Running)?;
        Ok(true)
    }

    async fn capabilities(&self) -> Result<TunnelCapabilities, TunnelError> {
        Ok(TunnelCapabilities {
            platform: if cfg!(target_os = "macos") {
                TunnelPlatform::Macos
            } else {
                TunnelPlatform::Linux
            },
            android_api_level: None,
            address_split_tunnel: true,
            application_split_tunnel: false,
        })
    }
}

fn require_state(response: Response, expected: ServiceTunnelState) -> Result<(), TunnelError> {
    validate_response(&response)?;
    if response.state == Some(expected) {
        Ok(())
    } else {
        Err(TunnelError::Backend(
            "unexpected_tunnel_service_state".to_string(),
        ))
    }
}

fn validate_response(response: &Response) -> Result<(), TunnelError> {
    if response.protocol_version != PROTOCOL_VERSION {
        return Err(TunnelError::Backend("unsupported_protocol".to_string()));
    }
    if !response.ok {
        return Err(TunnelError::Backend(
            response
                .error_code
                .clone()
                .unwrap_or_else(|| "service_unavailable".to_string()),
        ));
    }
    Ok(())
}

fn to_tunnel_error(error: ServiceError) -> TunnelError {
    TunnelError::Backend(error.code().to_string())
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn encode_request(request: &Request) -> Result<Vec<u8>, ServiceError> {
    encode_frame(request)
}

pub fn decode_request(frame: &[u8]) -> Result<Request, ServiceError> {
    decode_frame(frame)
}

pub fn encode_response(response: &Response) -> Result<Vec<u8>, ServiceError> {
    encode_frame(response)
}

pub fn decode_response(frame: &[u8]) -> Result<Response, ServiceError> {
    decode_frame(frame)
}

fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ServiceError> {
    let body = serde_json::to_vec(value).map_err(|_| ServiceError::InvalidRequest)?;
    if body.len() > MAX_FRAME_SIZE {
        return Err(ServiceError::FrameTooLarge);
    }

    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

fn decode_frame<T: for<'de> Deserialize<'de>>(frame: &[u8]) -> Result<T, ServiceError> {
    let length_bytes: [u8; 4] = frame
        .get(..4)
        .ok_or(ServiceError::TruncatedFrame)?
        .try_into()
        .map_err(|_| ServiceError::TruncatedFrame)?;
    let body_length = u32::from_le_bytes(length_bytes) as usize;
    if body_length > MAX_FRAME_SIZE {
        return Err(ServiceError::FrameTooLarge);
    }
    if frame.len() != body_length + 4 {
        return Err(ServiceError::TruncatedFrame);
    }

    serde_json::from_slice(&frame[4..]).map_err(|_| ServiceError::InvalidRequest)
}

#[cfg(test)]
mod service_error_tests {
    use super::ServiceError;

    #[test]
    fn exposes_only_allowlisted_backend_codes() {
        assert_eq!(
            ServiceError::Backend("interface_up_failed".to_string()).code(),
            "interface_up_failed"
        );
        assert_eq!(
            ServiceError::Backend("route_conflict".to_string()).code(),
            "route_conflict"
        );
        assert_eq!(
            ServiceError::Backend("raw operating system error".to_string()).code(),
            "service_unavailable"
        );
        assert_eq!(
            ServiceError::Backend("amneziawg_configuration_failed".to_string()).code(),
            "amneziawg_configuration_failed"
        );
        assert_eq!(
            ServiceError::Backend("amneziawg_profile_mismatch".to_string()).code(),
            "amneziawg_profile_mismatch"
        );
        assert_eq!(
            ServiceError::Backend("network_configuration_failed".to_string()).code(),
            "network_configuration_failed"
        );
        assert_eq!(
            ServiceError::Backend("tunnel_not_running".to_string()).code(),
            "tunnel_not_running"
        );
        assert_eq!(
            ServiceError::Backend("endpoint_route_unavailable".to_string()).code(),
            "endpoint_route_unavailable"
        );
        assert_eq!(
            ServiceError::Backend("endpoint_route_lost".to_string()).code(),
            "endpoint_route_lost"
        );
    }
}
