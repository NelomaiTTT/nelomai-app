use async_trait::async_trait;
use nelomai_client_tunnel::{
    DesktopTunnelOptions, TunnelCapabilities, TunnelController, TunnelError, TunnelMetrics,
    TunnelPlatform, TunnelStartRequest, TunnelStatus,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(windows)]
pub mod windows;

pub const PROTOCOL_VERSION: u16 = 4;
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const MANAGER_SERVICE_NAME: &str = "NelomaiTunnelManager";
pub const TUNNEL_SERVICE_NAME: &str = "WireGuardTunnel$Nelomai";
pub const PIPE_NAME: &str = r"\\.\pipe\NelomaiTunnelManager";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStartMode {
    Automatic,
    OnDemand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    pub name: String,
    pub display_name: String,
    pub executable_path: PathBuf,
    pub arguments: Vec<String>,
    pub dependencies: Vec<String>,
    pub start_mode: ServiceStartMode,
    pub run_as_local_system: bool,
    pub unrestricted_service_sid: bool,
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
    #[serde(default)]
    pub physical_network_fingerprint: Option<String>,
    #[serde(default)]
    pub metrics: Option<TunnelMetrics>,
    pub error_code: Option<String>,
}

impl Response {
    pub fn success(state: Option<ServiceTunnelState>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            ok: true,
            state,
            service_version: None,
            physical_network_fingerprint: None,
            metrics: None,
            error_code: None,
        }
    }

    pub fn failure(error_code: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            ok: false,
            state: None,
            service_version: None,
            physical_network_fingerprint: None,
            metrics: None,
            error_code: Some(error_code.into()),
        }
    }
}

pub enum Request {
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

    pub fn protocol_version(&self) -> u16 {
        match self {
            Self::Start {
                protocol_version, ..
            }
            | Self::Stop { protocol_version }
            | Self::Status { protocol_version }
            | Self::Version { protocol_version }
            | Self::PhysicalNetworkFingerprint { protocol_version }
            | Self::Metrics {
                protocol_version, ..
            } => *protocol_version,
        }
    }
}

impl PartialEq for Request {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Start {
                    protocol_version: left_version,
                    configuration: left_configuration,
                    options: left_options,
                },
                Self::Start {
                    protocol_version: right_version,
                    configuration: right_configuration,
                    options: right_options,
                },
            ) => {
                left_version == right_version
                    && left_configuration == right_configuration
                    && left_options == right_options
            }
            (
                Self::Stop {
                    protocol_version: left,
                },
                Self::Stop {
                    protocol_version: right,
                },
            )
            | (
                Self::Status {
                    protocol_version: left,
                },
                Self::Status {
                    protocol_version: right,
                },
            )
            | (
                Self::Version {
                    protocol_version: left,
                },
                Self::Version {
                    protocol_version: right,
                },
            )
            | (
                Self::PhysicalNetworkFingerprint {
                    protocol_version: left,
                },
                Self::PhysicalNetworkFingerprint {
                    protocol_version: right,
                },
            ) => left == right,
            (
                Self::Metrics {
                    protocol_version: left_version,
                    probe: left_probe,
                },
                Self::Metrics {
                    protocol_version: right_version,
                    probe: right_probe,
                },
            ) => left_version == right_version && left_probe == right_probe,
            _ => false,
        }
    }
}

impl Eq for Request {}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum RequestRef<'a> {
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
}

impl Serialize for Request {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
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
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum RequestOwned {
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
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match RequestOwned::deserialize(deserializer)? {
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
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    pub sid: String,
    pub process_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
pub struct ClientPolicy {
    pub owner_sid: String,
    pub installed_client_path: PathBuf,
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
    #[error("service path cannot be quoted safely")]
    UnsafePath,
    #[error("service protocol version is unsupported")]
    UnsupportedProtocol,
    #[error("Windows tunnel backend failed: {0}")]
    Backend(String),
}

impl ServiceError {
    pub fn code(&self) -> &str {
        match self {
            Self::FrameTooLarge => "frame_too_large",
            Self::TruncatedFrame => "truncated_frame",
            Self::InvalidRequest => "invalid_request",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsafePath => "unsafe_path",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::Backend(code) => stable_route_error_code(code).unwrap_or("service_unavailable"),
        }
    }
}

fn stable_route_error_code(code: &str) -> Option<&'static str> {
    Some(match code {
        "service_timeout" => "service_timeout",
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
        "route_del_failed" => "route_del_failed",
        "route_delete_failed" => "route_delete_failed",
        "route_command_failed" => "route_command_failed",
        "route_command_unavailable" => "route_command_unavailable",
        "route_table_unavailable" => "route_table_unavailable",
        "ip_command_unavailable" => "ip_command_unavailable",
        "physical_egress_unavailable" => "physical_egress_unavailable",
        "local_networks_unavailable" => "local_networks_unavailable",
        _ => return None,
    })
}

pub trait ServiceTunnelBackend {
    fn start(
        &mut self,
        configuration: &str,
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
}

pub struct TunnelRequestHandler<B> {
    backend: B,
    service_version: String,
}

impl<B: ServiceTunnelBackend> TunnelRequestHandler<B> {
    pub fn new(backend: B, service_version: impl Into<String>) -> Self {
        Self {
            backend,
            service_version: service_version.into(),
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn handle(&mut self, request: Request) -> Response {
        if request.protocol_version() != PROTOCOL_VERSION {
            return Response::failure(ServiceError::UnsupportedProtocol.code());
        }

        let result = match request {
            Request::Start {
                configuration,
                options,
                ..
            } => options
                .validate()
                .map_err(|_| ServiceError::InvalidRequest)
                .and_then(|_| {
                    let configuration =
                        prepare_windows_wireguard_configuration(configuration.as_str(), &options);
                    self.backend.start(configuration.as_str(), &options)
                })
                .map(|state| Response::success(Some(state))),
            Request::Stop { .. } => self
                .backend
                .stop()
                .map(|state| Response::success(Some(state))),
            Request::Status { .. } => self
                .backend
                .status()
                .map(|state| Response::success(Some(state))),
            Request::Version { .. } => {
                let mut response = Response::success(None);
                response.service_version = Some(self.service_version.clone());
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
        };

        result.unwrap_or_else(|error| Response::failure(error.code()))
    }
}

fn prepare_windows_wireguard_configuration(
    configuration: &str,
    options: &DesktopTunnelOptions,
) -> Zeroizing<String> {
    let address_split_active = options.policy_hash.is_some()
        && (options.exclude_local_networks || !options.excluded_ipv4_cidrs.is_empty());
    if !address_split_active {
        return Zeroizing::new(configuration.to_string());
    }

    let mut in_peer = false;
    let mut output = String::with_capacity(configuration.len() + 32);
    for segment in configuration.split_inclusive('\n') {
        let (line_with_optional_cr, newline) = segment
            .strip_suffix('\n')
            .map_or((segment, ""), |line| (line, "\n"));
        let (line, carriage_return) = line_with_optional_cr
            .strip_suffix('\r')
            .map_or((line_with_optional_cr, ""), |line| (line, "\r"));
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_peer = trimmed.eq_ignore_ascii_case("[Peer]");
        }

        if in_peer {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim().eq_ignore_ascii_case("AllowedIPs") {
                    let mut changed = false;
                    let mut values = Vec::new();
                    for value in value.split(',').map(str::trim) {
                        match value {
                            "0.0.0.0/0" => {
                                changed = true;
                                values.extend(["0.0.0.0/1", "128.0.0.0/1"]);
                            }
                            "::/0" => {
                                changed = true;
                                values.extend(["::/1", "8000::/1"]);
                            }
                            value => values.push(value),
                        }
                    }
                    if changed {
                        output.push_str(key);
                        output.push('=');
                        output.push(' ');
                        output.push_str(&values.join(", "));
                        output.push_str(carriage_return);
                        output.push_str(newline);
                        continue;
                    }
                }
            }
        }

        output.push_str(line);
        output.push_str(carriage_return);
        output.push_str(newline);
    }
    Zeroizing::new(output)
}

#[async_trait]
pub trait ServiceTransport: Send + Sync {
    async fn exchange(&self, request: Request) -> Result<Response, ServiceError>;
}

pub struct WindowsTunnelController<T> {
    transport: T,
}

impl<T> WindowsTunnelController<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: ServiceTransport> WindowsTunnelController<T> {
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
}

#[async_trait]
impl<T: ServiceTransport> TunnelController for WindowsTunnelController<T> {
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

    async fn capabilities(&self) -> Result<TunnelCapabilities, TunnelError> {
        Ok(TunnelCapabilities {
            platform: TunnelPlatform::Windows,
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

pub fn authorize_client(
    policy: &ClientPolicy,
    identity: &ClientIdentity,
) -> Result<(), ServiceError> {
    let sid_matches = identity.sid == policy.owner_sid;
    let path_matches = normalize_windows_path(&identity.process_path)
        == normalize_windows_path(&policy.installed_client_path);

    if sid_matches && path_matches {
        Ok(())
    } else {
        Err(ServiceError::UnauthorizedClient)
    }
}

pub fn service_command_line(
    executable: &Path,
    configuration: &Path,
) -> Result<String, ServiceError> {
    let executable = executable.to_string_lossy();
    let configuration = configuration.to_string_lossy();
    if executable.is_empty()
        || configuration.is_empty()
        || executable.contains('"')
        || configuration.contains('"')
    {
        return Err(ServiceError::UnsafePath);
    }

    Ok(format!(
        "\"{executable}\" --wireguard-service \"{configuration}\""
    ))
}

pub fn manager_service_spec(executable: &Path) -> Result<ServiceSpec, ServiceError> {
    validate_safe_path(executable)?;
    Ok(ServiceSpec {
        name: MANAGER_SERVICE_NAME.to_string(),
        display_name: "Nelomai Tunnel Manager".to_string(),
        executable_path: executable.to_path_buf(),
        arguments: vec!["--manager-service".to_string()],
        dependencies: Vec::new(),
        start_mode: ServiceStartMode::Automatic,
        run_as_local_system: true,
        unrestricted_service_sid: false,
    })
}

pub fn tunnel_service_spec(
    executable: &Path,
    configuration: &Path,
) -> Result<ServiceSpec, ServiceError> {
    validate_safe_path(executable)?;
    validate_safe_path(configuration)?;
    Ok(ServiceSpec {
        name: TUNNEL_SERVICE_NAME.to_string(),
        display_name: "Nelomai WireGuard Tunnel".to_string(),
        executable_path: executable.to_path_buf(),
        arguments: vec![
            "--wireguard-service".to_string(),
            configuration.to_string_lossy().into_owned(),
        ],
        dependencies: vec!["Nsi".to_string(), "TcpIp".to_string()],
        start_mode: ServiceStartMode::Automatic,
        run_as_local_system: true,
        unrestricted_service_sid: true,
    })
}

pub fn private_directory_security_descriptor() -> &'static str {
    "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
}

pub fn pipe_security_descriptor(owner_sid: &str) -> Result<String, ServiceError> {
    if !is_valid_sid_string(owner_sid) {
        return Err(ServiceError::UnauthorizedClient);
    }
    Ok(format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{owner_sid})"
    ))
}

fn is_valid_sid_string(sid: &str) -> bool {
    let mut parts = sid.split('-');
    if parts.next() != Some("S") {
        return false;
    }
    let Some(revision) = parts.next() else {
        return false;
    };
    if revision.parse::<u8>().is_err() {
        return false;
    }

    let numeric_parts: Vec<&str> = parts.collect();
    numeric_parts.len() >= 2
        && numeric_parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn validate_safe_path(path: &Path) -> Result<(), ServiceError> {
    let path = path.to_string_lossy();
    if path.is_empty() || path.contains('"') {
        Err(ServiceError::UnsafePath)
    } else {
        Ok(())
    }
}

fn normalize_windows_path(path: &Path) -> String {
    let normalized = path
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase();
    if let Some(path) = normalized.strip_prefix(r"\\?\unc\") {
        format!(r"\\{path}")
    } else {
        normalized
            .strip_prefix(r"\\?\")
            .unwrap_or(&normalized)
            .to_string()
    }
}

#[cfg(test)]
mod service_error_tests {
    use super::ServiceError;

    #[test]
    fn exposes_only_allowlisted_backend_codes() {
        assert_eq!(
            ServiceError::Backend("route_conflict".to_string()).code(),
            "route_conflict"
        );
        assert_eq!(
            ServiceError::Backend("raw operating system error".to_string()).code(),
            "service_unavailable"
        );
    }
}
