use serde::{Deserialize, Serialize};
use std::fmt;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use zeroize::Zeroize;

#[derive(Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum HelperRequest {
    Probe,
    StartTunnel { config: String },
    StopTunnel,
}

impl Drop for HelperRequest {
    fn drop(&mut self) {
        if let Self::StartTunnel { config } = self {
            config.zeroize();
        }
    }
}

impl fmt::Debug for HelperRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Probe => formatter.write_str("Probe"),
            Self::StartTunnel { .. } => formatter
                .debug_struct("StartTunnel")
                .field("config", &"[REDACTED]")
                .finish(),
            Self::StopTunnel => formatter.write_str("StopTunnel"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HelperResponse {
    pub ok: bool,
    pub message: String,
}

pub fn authorize_peer(actual_uid: u32, allowed_uid: u32) -> io::Result<()> {
    if actual_uid == allowed_uid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("peer uid {actual_uid} is not authorized"),
        ))
    }
}

#[cfg(target_os = "macos")]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: getpeereid only writes to the provided uid/gid values and does
    // not retain either pointer.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result == 0 {
        Ok(uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes a ucred value into a correctly sized buffer.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut libc::c_void,
            &mut length,
        )
    };
    if result == 0 {
        Ok(credentials.uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn current_process_is_authorized_over_local_socket() {
        let (server, _client) = UnixStream::pair().expect("create socket pair");
        let uid = peer_uid(&server).expect("read peer uid");

        authorize_peer(uid, unsafe { libc::geteuid() }).expect("authorize current user");
    }

    #[test]
    fn another_uid_is_rejected() {
        let current_uid = unsafe { libc::geteuid() };
        let another_uid = if current_uid == u32::MAX {
            current_uid - 1
        } else {
            current_uid + 1
        };

        let error = authorize_peer(another_uid, current_uid).expect_err("reject another uid");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn tunnel_configuration_is_redacted_from_debug_output() {
        let secret = "PrivateKey = should-never-reach-logs";
        let request = HelperRequest::StartTunnel {
            config: secret.to_string(),
        };
        let output = format!("{request:?}");

        assert_eq!(output, "StartTunnel { config: \"[REDACTED]\" }");
        assert!(!output.contains(secret));
    }

    #[test]
    fn tunnel_configuration_is_carried_in_json_body() {
        let request = HelperRequest::StartTunnel {
            config: "PrivateKey = local-socket-only".to_string(),
        };
        let json = serde_json::to_string(&request).expect("serialize request");

        assert!(json.contains("local-socket-only"));
        assert!(!std::env::args().any(|argument| argument.contains("local-socket-only")));
    }

    #[test]
    fn unknown_command_is_rejected() {
        let error = serde_json::from_str::<HelperRequest>(r#"{"command":"run_shell"}"#)
            .expect_err("reject unknown command");

        assert!(error.to_string().contains("unknown variant"));
    }
}
