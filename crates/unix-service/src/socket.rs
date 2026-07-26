use crate::{
    authorize_peer, decode_request, decode_response, encode_request, encode_response,
    ClientIdentity, ClientPolicy, Request, Response, ServiceError, ServiceTransport,
    ServiceTunnelBackend, TunnelRequestHandler, MAX_FRAME_SIZE,
};
use async_trait::async_trait;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub struct UnixSocketTransport {
    path: PathBuf,
}

pub fn prepare_runtime_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "runtime directory is not trusted",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
        }
        Err(error) => return Err(error),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

impl UnixSocketTransport {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn exchange_blocking(&self, request: Request) -> Result<Response, ServiceError> {
        let mut stream = UnixStream::connect(&self.path).map_err(transport_error)?;
        configure_stream(&stream)?;
        let frame = encode_request(&request)?;
        stream.write_all(&frame).map_err(transport_error)?;
        let response = read_frame(&mut stream)?;
        decode_response(&response)
    }
}

#[async_trait]
impl ServiceTransport for UnixSocketTransport {
    async fn exchange(&self, request: Request) -> Result<Response, ServiceError> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || Self::new(path).exchange_blocking(request))
            .await
            .map_err(|_| ServiceError::Backend("helper_task_failed".to_string()))?
    }
}

pub fn bind_listener(path: &Path, socket_owner_uid: u32) -> io::Result<UnixListener> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket has no parent"))?;
    validate_parent_directory(parent)?;

    if let Ok(metadata) = fs::symlink_metadata(path) {
        let trusted_owner =
            metadata.uid() == unsafe { libc::geteuid() } || metadata.uid() == socket_owner_uid;
        if !metadata.file_type().is_socket() || !trusted_owner {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing to replace an untrusted socket path",
            ));
        }
        fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    if unsafe { libc::chown(path_to_c_string(path)?.as_ptr(), socket_owner_uid, u32::MAX) } != 0 {
        let error = io::Error::last_os_error();
        let _ = fs::remove_file(path);
        return Err(error);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn serve_one<B: ServiceTunnelBackend>(
    listener: &UnixListener,
    policy: &ClientPolicy,
    handler: &mut TunnelRequestHandler<B>,
) -> Result<(), ServiceError> {
    let (mut stream, _) = listener.accept().map_err(transport_error)?;
    configure_stream(&stream)?;
    let identity = ClientIdentity {
        uid: peer_uid(&stream).map_err(transport_error)?,
    };
    authorize_peer(policy, &identity)?;

    let response = match read_frame(&mut stream).and_then(|frame| decode_request(&frame)) {
        Ok(request) => handler.handle(request),
        Err(error) => Response::failure(error.code()),
    };
    let frame = encode_response(&response)?;
    stream.write_all(&frame).map_err(transport_error)?;
    stream.flush().map_err(transport_error)
}

#[cfg(target_os = "macos")]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: getpeereid writes to two correctly sized values and retains no pointers.
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
    // SAFETY: getsockopt writes one ucred into a correctly sized buffer.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut libc::c_void,
            &mut length,
        )
    };
    if result == 0 && length as usize == std::mem::size_of::<libc::ucred>() {
        Ok(credentials.uid)
    } else if result == 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid peer credentials",
        ))
    } else {
        Err(io::Error::last_os_error())
    }
}

fn validate_parent_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || mode & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket directory is not trusted",
        ));
    }
    Ok(())
}

fn configure_stream(stream: &UnixStream) -> Result<(), ServiceError> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(transport_error)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(transport_error)
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, ServiceError> {
    let mut length_bytes = [0; 4];
    stream
        .read_exact(&mut length_bytes)
        .map_err(|_| ServiceError::TruncatedFrame)?;
    let body_length = u32::from_le_bytes(length_bytes) as usize;
    if body_length > MAX_FRAME_SIZE {
        return Err(ServiceError::FrameTooLarge);
    }

    let mut frame = Vec::with_capacity(body_length + 4);
    frame.extend_from_slice(&length_bytes);
    frame.resize(body_length + 4, 0);
    stream
        .read_exact(&mut frame[4..])
        .map_err(|_| ServiceError::TruncatedFrame)?;
    Ok(frame)
}

fn transport_error(error: io::Error) -> ServiceError {
    ServiceError::Backend(error.to_string())
}

fn path_to_c_string(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a null byte"))
}
