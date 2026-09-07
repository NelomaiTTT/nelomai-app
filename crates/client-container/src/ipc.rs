//! Private inherited auth/control protocol. Endpoint possession is not a
//! verified launch: the Task9 launcher must supply the separate launch binding.
use crate::ScopeStamp;
use nelomai_client_api::{AccessSnapshot, RuntimeAuthState, RuntimeLogin};
use nelomai_client_storage::RuntimeAuthScope;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout_at, Duration, Instant};
mod child_admission;
pub use child_admission::{ChildAdmission, RuntimeRecordInventory, ScopeAdmission};
mod remote;
mod transport;
pub use remote::{
    LaunchBinding, OwnerService, PrivateBackgroundDispatcher, PrivateRuntimeAuthClient, RemoteOwner,
};
#[cfg(test)]
mod tests;
#[cfg(windows)]
pub mod windows;

pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const REQUEST_BUDGET: Duration = Duration::from_secs(10);
pub const MAX_PENDING: usize = 8;
pub const OUTBOX_CAPACITY: usize = 32;

#[derive(Debug, Clone, Copy, thiserror::Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrivateError {
    #[error("private channel closed")]
    Closed,
    #[error("private request deadline exceeded")]
    Timeout,
    #[error("invalid private protocol")]
    Protocol,
    #[error("private request cancelled")]
    Cancelled,
    #[error("authentication recovery required")]
    RecoveryRequired,
    #[error("authentication outcome unknown")]
    OutcomeUnknown,
    #[error("access unavailable")]
    AccessUnavailable,
    #[error("authentication service failed")]
    Service,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum AuthRequestV1 {
    State,
    Owner {
        request: crate::host::HostRequestV1,
    },
    Login {
        stamp: Option<ScopeStamp>,
        request: RuntimeLogin,
    },
    AccessToken {
        stamp: Option<ScopeStamp>,
        stale: Option<AccessSnapshot>,
    },
    Logout {
        stamp: Option<ScopeStamp>,
        cancel_login_request: Option<u64>,
    },
    /// Only an owner-side action/status request, never native credentials/tickets.
    BackgroundCredential {
        stamp: Option<ScopeStamp>,
        action: BackgroundAction,
    },
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundAction {
    Provision,
    Recover,
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum AuthResponseV1 {
    Owner {
        response: crate::host::HostResponseV1,
    },
    State {
        stamp: ScopeStamp,
        state: RuntimeAuthState,
    },
    Access {
        stamp: ScopeStamp,
        access: AccessSnapshot,
    },
    Done,
    Error {
        error: PrivateError,
    },
}

/// Incarnation plus monotonically allocated request IDs are local capabilities
/// on one inherited channel. No lease survives peer replacement or revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedLease {
    pub incarnation: String,
    pub request: u64,
    pub cancel_generation: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ControlV1 {
    Prepare {
        incarnation: String,
    },
    CommitAdmission {
        lease: PreparedLease,
        scope: RuntimeAuthScope,
    },
    ValidateScope {
        lease: PreparedLease,
        scope: RuntimeAuthScope,
    },
    Grant {
        lease: PreparedLease,
        scope: RuntimeAuthScope,
        response: Box<Option<(u64, AuthResponseV1)>>,
    },
    Abort {
        lease: PreparedLease,
    },
    Revoke,
    Stop,
    CheckScope {
        scope: RuntimeAuthScope,
    },
    CleanupSourceSnapshot {
        lease: PreparedLease,
        scope: Option<RuntimeAuthScope>,
    },
    CompleteCleanup {
        lease: PreparedLease,
        snapshot: nelomai_client_storage::RuntimeCleanupSnapshotV1,
        scope: RuntimeAuthScope,
    },
    CompleteLogout {
        lease: PreparedLease,
        receipt: nelomai_client_storage::CompletedRuntimeLogoutV1,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum ControlAckV1 {
    Prepared {
        lease: PreparedLease,
    },
    CleanupSnapshot {
        snapshot: nelomai_client_storage::RuntimeCleanupSnapshotV1,
    },
    Committed,
    Done,
    Error {
        error: PrivateError,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    tag = "direction",
    content = "body",
    rename_all = "snake_case"
)]
pub enum MessageV1 {
    Request(AuthRequestV1),
    Response(AuthResponseV1),
    Control(ControlV1),
    Ack(ControlAckV1),
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrameV1 {
    pub version: u32,
    pub id: u64,
    pub remaining_ms: u64,
    pub message: MessageV1,
}
impl FrameV1 {
    pub fn new(id: u64, message: MessageV1) -> Self {
        Self {
            version: 1,
            id,
            remaining_ms: 10_000,
            message,
        }
    }
}

/// The announced length is checked before allocation; errors never carry wire
/// bytes, serde diagnostics, tokens, usernames or passwords.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    deadline: Instant,
) -> Result<FrameV1, PrivateError> {
    timeout_at(deadline, async {
        let length = reader.read_u32().await.map_err(|_| PrivateError::Closed)? as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            return Err(PrivateError::Protocol);
        }
        let mut bytes = vec![0; length];
        reader
            .read_exact(&mut bytes)
            .await
            .map_err(|_| PrivateError::Closed)?;
        let frame: FrameV1 = serde_json::from_slice(&bytes).map_err(|_| PrivateError::Protocol)?;
        if frame.version != 1
            || frame.id == 0
            || frame.remaining_ms == 0
            || frame.remaining_ms > 10_000
        {
            return Err(PrivateError::Protocol);
        }
        Ok(frame)
    })
    .await
    .map_err(|_| PrivateError::Timeout)?
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut frame: FrameV1,
    deadline: Instant,
) -> Result<(), PrivateError> {
    validate_frame_size(&frame)?;
    frame.remaining_ms = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(10_000) as u64;
    if frame.remaining_ms == 0 {
        return Err(PrivateError::Timeout);
    }
    let bytes = serde_json::to_vec(&frame).map_err(|_| PrivateError::Protocol)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(PrivateError::Protocol);
    }
    timeout_at(deadline, async {
        writer
            .write_u32(bytes.len() as u32)
            .await
            .map_err(|_| PrivateError::Closed)?;
        writer
            .write_all(&bytes)
            .await
            .map_err(|_| PrivateError::Closed)?;
        writer.flush().await.map_err(|_| PrivateError::Closed)
    })
    .await
    .map_err(|_| PrivateError::Timeout)?
}

pub(super) fn validate_frame_size(frame: &FrameV1) -> Result<(), PrivateError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_FRAME_BYTES - self.0 {
                return Err(std::io::Error::other("private frame too large"));
            }
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter(0), frame).map_err(|_| PrivateError::Protocol)
}

/// Unnamed, nonblocking Unix socketpair. Both descriptors are CLOEXEC by
/// default. Task9 selectively transfers only the child endpoint before exec.
#[cfg(unix)]
pub fn private_socketpair() -> std::io::Result<(tokio::net::UnixStream, tokio::net::UnixStream)> {
    tokio::net::UnixStream::pair()
}
