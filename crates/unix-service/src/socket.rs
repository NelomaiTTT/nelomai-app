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
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_WATCHDOG_TIMEOUT: Duration = Duration::from_secs(40);

struct RequestWatchdog {
    completed: Arc<(Mutex<bool>, Condvar)>,
}

impl RequestWatchdog {
    fn arm() -> Result<Self, ServiceError> {
        let completed = Arc::new((Mutex::new(false), Condvar::new()));
        let completed_for_thread = Arc::clone(&completed);
        std::thread::Builder::new()
            .name("nelomai-helper-watchdog".to_string())
            .spawn(move || {
                let (lock, condition) = &*completed_for_thread;
                let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let (guard, timeout) = condition
                    .wait_timeout_while(guard, REQUEST_WATCHDOG_TIMEOUT, |completed| !*completed)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if timeout.timed_out() && !*guard {
                    eprintln!("nelomai tunnel helper request watchdog expired");
                    std::process::exit(1);
                }
            })
            .map_err(transport_error)?;
        Ok(Self { completed })
    }

    fn complete(self) {
        let (lock, condition) = &*self.completed;
        let mut completed = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *completed = true;
        condition.notify_one();
    }
}

#[derive(Clone)]
pub struct UnixSocketTransport {
    path: PathBuf,
    dispatcher_path: Option<PathBuf>,
    common: Option<nelomai_contracts::dispatcher::CommonEngineBinding>,
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
        let path = path.into();
        let dispatcher_path = (path == Path::new(crate::DEFAULT_SOCKET_PATH))
            .then(|| PathBuf::from(crate::DISPATCHER_SOCKET_PATH));
        Self {
            path,
            dispatcher_path,
            common: None,
        }
    }

    pub fn with_dispatcher(path: impl Into<PathBuf>, dispatcher_path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            dispatcher_path: Some(dispatcher_path.into()),
            common: None,
        }
    }

    pub fn for_common(
        mut self,
        binding: nelomai_contracts::dispatcher::CommonEngineBinding,
    ) -> Self {
        self.common = Some(binding);
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn exchange_blocking(&self, request: Request) -> Result<Response, ServiceError> {
        if let Some(binding) = &self.common {
            return binding
                .with_identity(
                    matches!(
                        request,
                        Request::Stop { .. } | Request::Status { .. } | Request::Version { .. }
                    ),
                    |expected| Ok(self.exchange_bound(request, expected)),
                )
                .map_err(|_| ServiceError::UnauthorizedClient)?;
        }
        self.exchange_bound(request, None)
    }

    fn exchange_bound(
        &self,
        request: Request,
        expected: Option<&nelomai_contracts::dispatcher::EngineIdentity>,
    ) -> Result<Response, ServiceError> {
        if request.protocol_version() != crate::PROTOCOL_VERSION {
            return Err(ServiceError::UnsupportedProtocol);
        }
        if let Some(dispatcher_path) = &self.dispatcher_path {
            use nelomai_contracts::dispatcher as d;
            let dispatcher_exchange =
                |request: &d::DispatcherRequest| dispatcher_exchange_at(dispatcher_path, request);
            let version = dispatcher_exchange(&d::DispatcherRequest::Version {
                contract_version: 1,
            })?;
            let reported = version
                .identity
                .filter(|_| version.ok && version.contract_version == 1)
                .ok_or(ServiceError::UnauthorizedClient)?;
            if expected.is_some_and(|expected| {
                expected.manifest_sha256 != reported.manifest_sha256
                    || expected.container_version != reported.container_version
                    || version.running && expected != &reported
            }) {
                return Err(ServiceError::UnauthorizedClient);
            }
            let identity = expected.unwrap_or(&reported).clone();
            if matches!(request, Request::Stop { .. }) {
                let stopped = dispatcher_exchange(&d::DispatcherRequest::Stop {
                    contract_version: 1,
                    identity: identity.clone(),
                })?;
                return if stopped.ok
                    && !stopped.running
                    && stopped.contract_version == 1
                    && stopped.identity.as_ref() == Some(&identity)
                {
                    Ok(Response::success(Some(crate::ServiceTunnelState::Stopped)))
                } else {
                    Err(ServiceError::Backend("dispatcher_stop_failed".into()))
                };
            }
            if !matches!(request, Request::Start { .. }) {
                if !version.running {
                    match request {
                        Request::Status { .. } => {
                            return Ok(Response::success(Some(crate::ServiceTunnelState::Stopped)));
                        }
                        Request::Version { .. } => {
                            let mut response = Response::success(None);
                            response.service_version = Some(identity.runtime_version);
                            return Ok(response);
                        }
                        // Linux's authenticated private endpoint can read persisted
                        // diagnostics without creating a tunnel engine.
                        #[cfg(any(target_os = "linux", test))]
                        Request::Diagnostics { .. } => {}
                        _ => return Err(ServiceError::Backend("engine_not_running".into())),
                    }
                }
            } else {
                let started = dispatcher_exchange(&d::DispatcherRequest::Start {
                    contract_version: 1,
                    identity: identity.clone(),
                })?;
                if !started.ok
                    || !started.running
                    || started.contract_version != 1
                    || started.identity.as_ref() != Some(&identity)
                {
                    return Err(ServiceError::Backend("dispatcher_start_failed".into()));
                }
            }
        }
        let mut stream = UnixStream::connect(&self.path).map_err(transport_error)?;
        configure_stream(&stream)?;
        let frame = encode_request(&request)?;
        stream.write_all(&frame).map_err(transport_error)?;
        let response = read_frame(&mut stream)?;
        decode_response(&response)
    }
}

pub fn dispatcher_exchange(
    request: &nelomai_contracts::dispatcher::DispatcherRequest,
) -> Result<nelomai_contracts::dispatcher::DispatcherResponse, ServiceError> {
    dispatcher_exchange_at(Path::new(crate::DISPATCHER_SOCKET_PATH), request)
}

fn dispatcher_exchange_at(
    path: &Path,
    request: &nelomai_contracts::dispatcher::DispatcherRequest,
) -> Result<nelomai_contracts::dispatcher::DispatcherResponse, ServiceError> {
    use nelomai_contracts::dispatcher as d;
    let mut stream = UnixStream::connect(path).map_err(transport_error)?;
    configure_stream(&stream)?;
    stream
        .write_all(&d::encode_frame(request).map_err(transport_error)?)
        .map_err(transport_error)?;
    let frame = d::read_frame(&mut stream, d::MAX_DISPATCHER_FRAME).map_err(transport_error)?;
    serde_json::from_slice(d::frame_body(&frame, d::MAX_DISPATCHER_FRAME).map_err(transport_error)?)
        .map_err(|_| ServiceError::InvalidRequest)
}

#[async_trait]
impl ServiceTransport for UnixSocketTransport {
    async fn exchange(&self, request: Request) -> Result<Response, ServiceError> {
        let transport = self.clone();
        tokio::task::spawn_blocking(move || transport.exchange_blocking(request))
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
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    if unsafe { libc::chown(path_to_c_string(path)?.as_ptr(), socket_owner_uid, u32::MAX) } != 0 {
        let error = io::Error::last_os_error();
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(listener)
}

pub fn serve_one<B: ServiceTunnelBackend>(
    listener: &UnixListener,
    policy: &ClientPolicy,
    handler: &mut TunnelRequestHandler<B>,
) -> Result<(), ServiceError> {
    let (mut stream, _) = listener.accept().map_err(transport_error)?;
    configure_stream(&stream)?;
    let identity = peer_identity(&stream).map_err(transport_error)?;
    authorize_peer(policy, &identity)?;

    let response = match read_frame(&mut stream).and_then(|frame| decode_request(&frame)) {
        Ok(request) => {
            let watchdog = RequestWatchdog::arm()?;
            let response = handler.handle(request);
            watchdog.complete();
            response
        }
        Err(error) => Response::failure(error.code()),
    };
    let frame = encode_response(&response)?;
    stream.write_all(&frame).map_err(transport_error)?;
    stream.flush().map_err(transport_error)
}

/// Credentials and executable identity come from the connected kernel peer,
/// never from request fields. Failure to resolve the process is fail-closed.
pub fn peer_identity(stream: &UnixStream) -> io::Result<ClientIdentity> {
    let uid = peer_uid(stream)?;
    #[cfg(target_os = "linux")]
    let process_path = {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        if result != 0
            || length as usize != std::mem::size_of::<libc::ucred>()
            || credentials.pid <= 0
            || credentials.uid != uid
        {
            return Err(io::Error::other("peer identity unavailable"));
        }
        fs::read_link(format!("/proc/{}/exe", credentials.pid))?
    };
    #[cfg(target_os = "macos")]
    let process_path = {
        let mut pid: libc::pid_t = 0;
        let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                0,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut length,
            )
        };
        if result != 0 || length as usize != std::mem::size_of::<libc::pid_t>() || pid <= 0 {
            return Err(io::Error::other("peer process unavailable"));
        }
        let mut path = vec![0u8; 4096];
        let count = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        let end = path
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| io::Error::other("invalid peer path"))?;
        use std::os::unix::ffi::OsStringExt;
        PathBuf::from(std::ffi::OsString::from_vec(path[..end].to_vec()))
    };
    Ok(ClientIdentity { uid, process_path })
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

pub fn serve_dispatcher_one(
    listener: &UnixListener,
    owner: &Arc<Mutex<nelomai_contracts::dispatcher::ProcessDispatcher>>,
    private: bool,
) -> Result<(), ServiceError> {
    let (mut stream, _) = listener.accept().map_err(transport_error)?;
    configure_stream(&stream)?;
    let watchdog = RequestWatchdog::arm()?;
    let result = (|| {
        let identity = peer_identity(&stream).map_err(transport_error)?;
        let address = listener.local_addr().map_err(transport_error)?;
        let directory = address
            .as_pathname()
            .and_then(Path::parent)
            .ok_or(ServiceError::InvalidRequest)?;
        serve_dispatcher_stream(&mut stream, &identity, owner, private, directory)
    })();
    watchdog.complete();
    result
}

fn serve_dispatcher_stream(
    stream: &mut (impl Read + Write),
    identity: &ClientIdentity,
    owner: &Arc<Mutex<nelomai_contracts::dispatcher::ProcessDispatcher>>,
    private: bool,
    _runtime_directory: &Path,
) -> Result<(), ServiceError> {
    use nelomai_contracts::dispatcher as d;
    let mut dispatcher = owner
        .try_lock()
        .map_err(|_| ServiceError::Backend("dispatcher_busy".into()))?;
    dispatcher
        .layout
        .broker
        .authorize(&identity.uid.to_string(), &identity.process_path)
        .map_err(|_| ServiceError::UnauthorizedClient)?;
    let frame = d::read_frame(
        stream,
        if private {
            MAX_FRAME_SIZE
        } else {
            d::MAX_DISPATCHER_FRAME
        },
    )
    .map_err(transport_error)?;
    let output = if private {
        #[cfg(any(target_os = "linux", test))]
        if matches!(
            decode_request(&frame),
            Ok(Request::Diagnostics {
                protocol_version: crate::PROTOCOL_VERSION
            })
        ) && !dispatcher
            .handle(
                d::DispatcherRequest::Status {
                    contract_version: 1,
                },
                &mut |_, _| Err(d::blocked()),
            )
            .running
        {
            let mut response = Response::success(None);
            response.diagnostics = Some(crate::backend::persisted_diagnostics(_runtime_directory));
            let output = encode_response(&response)?;
            drop(dispatcher);
            stream.write_all(&output).map_err(transport_error)?;
            return stream.flush().map_err(transport_error);
        }
        dispatcher
            .relay(&frame, &mut |_, _| Err(d::blocked()))
            .map_err(transport_error)?
    } else {
        let response = d::decode_request(&frame)
            .map(|request| dispatcher.handle(request, &mut |_, _| Err(d::blocked())))
            .unwrap_or_else(|_| d::DispatcherResponse::failure());
        d::encode_frame(&response).map_err(transport_error)?
    };
    // The reply can trigger the next request on the other socket before
    // write_all returns. Dispatch is complete; release ownership first.
    drop(dispatcher);
    stream.write_all(&output).map_err(transport_error)?;
    stream.flush().map_err(transport_error)
}

pub fn recover_dispatcher(
    owner: &mut nelomai_contracts::dispatcher::ProcessDispatcher,
) -> Result<(), ServiceError> {
    use nelomai_contracts::dispatcher as d;
    if !owner.installation.root.join(d::ACTIVE_ENGINE_NAME).exists() {
        return Ok(());
    }
    let watchdog = RequestWatchdog::arm()?;
    let response = owner.handle(
        d::DispatcherRequest::Stop {
            contract_version: 1,
            identity: owner.layout.identity.clone(),
        },
        &mut |_, _| Err(d::blocked()),
    );
    watchdog.complete();
    if response.ok {
        Ok(())
    } else {
        Err(ServiceError::Backend("dispatcher_recovery_pending".into()))
    }
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

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod dispatcher_test_support;

#[cfg(test)]
mod dispatcher_response_tests {
    use super::*;
    use nelomai_contracts::dispatcher as d;
    use std::sync::mpsc;

    #[tokio::test]
    async fn stopped_linux_diagnostics_read_private_logs_without_starting_engine() {
        let (root, owner) = super::dispatcher_test_support::owned_dispatcher();
        {
            let mut dispatcher = owner.lock().unwrap();
            let identity = dispatcher.layout.identity.clone();
            assert!(
                dispatcher
                    .handle(
                        d::DispatcherRequest::Start {
                            contract_version: 1,
                            identity: identity.clone()
                        },
                        &mut |_, _| Err(d::blocked())
                    )
                    .running
            );
            let stopped = dispatcher.handle(
                d::DispatcherRequest::Stop {
                    contract_version: 1,
                    identity,
                },
                &mut |_, _| Err(d::blocked()),
            );
            assert!(stopped.ok && !stopped.running);
        }
        fs::write(
            root.path().join("userspace-tunnel.log"),
            "ERROR: handshake timeout\n",
        )
        .unwrap();
        fs::set_permissions(
            root.path().join("userspace-tunnel.log"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let lifecycle_path = root.path().join("lifecycle.sock");
        let private_path = root.path().join("private.sock");
        let lifecycle = bind_listener(&lifecycle_path, unsafe { libc::geteuid() }).unwrap();
        let private = bind_listener(&private_path, unsafe { libc::geteuid() }).unwrap();
        private.set_nonblocking(true).unwrap();
        let lifecycle_owner = owner.clone();
        let lifecycle_thread =
            std::thread::spawn(move || serve_dispatcher_one(&lifecycle, &lifecycle_owner, false));
        let private_owner = owner.clone();
        let (done, finished) = mpsc::channel();
        let private_thread = std::thread::spawn(move || loop {
            if let Ok(()) = serve_dispatcher_one(&private, &private_owner, true) {
                break;
            }
            if finished.try_recv().is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        });
        let binding = d::CommonEngineBinding::default();
        binding
            .bind(owner.lock().unwrap().layout.identity.clone())
            .unwrap();
        let controller = crate::UnixTunnelController::new(
            UnixSocketTransport::with_dispatcher(private_path, lifecycle_path).for_common(binding),
        );
        let result = controller.diagnostics().await;
        let _ = done.send(());
        lifecycle_thread.join().unwrap().unwrap();
        private_thread.join().unwrap();
        let log = result.expect("stopped engine must not hide persisted diagnostics");
        assert!(log.contains("source=persisted"));
        assert!(log.contains("ERROR: handshake timeout"));
        assert!(!root.path().join(d::ACTIVE_ENGINE_NAME).exists());
        assert!(
            !owner
                .lock()
                .unwrap()
                .handle(
                    d::DispatcherRequest::Status {
                        contract_version: 1
                    },
                    &mut |_, _| Err(d::blocked())
                )
                .running
        );
        assert_eq!(
            fs::metadata(root.path().join("userspace-tunnel.log"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    struct PublishedResponseGate {
        stream: UnixStream,
        release: Option<mpsc::Receiver<()>>,
    }

    #[test]
    fn persisted_diagnostics_still_require_verified_broker_and_protocol() {
        let (root, owner) = super::dispatcher_test_support::owned_dispatcher();
        for peer in [
            ClientIdentity {
                uid: unsafe { libc::geteuid() } + 1,
                process_path: std::env::current_exe().unwrap(),
            },
            ClientIdentity {
                uid: unsafe { libc::geteuid() },
                process_path: PathBuf::from("/untrusted-client"),
            },
        ] {
            let mut stream = io::Cursor::new(encode_request(&Request::diagnostics()).unwrap());
            assert_eq!(
                serve_dispatcher_stream(&mut stream, &peer, &owner, true, root.path()),
                Err(ServiceError::UnauthorizedClient)
            );
            assert_eq!(
                stream.position(),
                0,
                "reject before decoding or reading logs"
            );
        }
        let peer = ClientIdentity {
            uid: unsafe { libc::geteuid() },
            process_path: std::env::current_exe().unwrap(),
        };
        let frame =
            d::encode_frame(&serde_json::json!({"command":"diagnostics","protocolVersion":0}))
                .unwrap();
        let mut stream = io::Cursor::new(frame.clone());
        assert!(serve_dispatcher_stream(&mut stream, &peer, &owner, true, root.path()).is_err());
        assert_eq!(
            stream.into_inner(),
            frame,
            "no logs sent on an unsupported protocol"
        );
        assert!(!root.path().join(d::ACTIVE_ENGINE_NAME).exists());
    }

    impl Read for PublishedResponseGate {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.stream.read(bytes)
        }
    }

    impl Write for PublishedResponseGate {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.stream.write_all(bytes)?;
            if let Some(release) = self.release.take() {
                release
                    .recv()
                    .map_err(|_| io::Error::other("response gate closed"))?;
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    #[test]
    fn dispatcher_still_rejects_a_request_while_mutation_owns_state() {
        let (_root, owner) = super::dispatcher_test_support::owned_dispatcher();
        let guard = owner.lock().unwrap();
        let peer = ClientIdentity {
            uid: unsafe { libc::geteuid() },
            process_path: std::env::current_exe().unwrap(),
        };
        let mut stream = io::Cursor::new(
            d::encode_frame(&d::DispatcherRequest::Version {
                contract_version: 1,
            })
            .unwrap(),
        );
        assert_eq!(
            serve_dispatcher_stream(&mut stream, &peer, &owner, false, _root.path()),
            Err(ServiceError::Backend("dispatcher_busy".into()))
        );
        assert_eq!(
            stream.position(),
            0,
            "busy request must not dispatch or publish"
        );
        drop(guard);
    }

    #[test]
    fn published_lifecycle_response_allows_private_request_before_write_returns() {
        let (root, owner) = super::dispatcher_test_support::owned_dispatcher();
        let identity = owner.lock().unwrap().layout.identity.clone();
        assert!(
            owner
                .lock()
                .unwrap()
                .handle(
                    d::DispatcherRequest::Start {
                        contract_version: 1,
                        identity: identity.clone(),
                    },
                    &mut |_, _| Err(d::blocked())
                )
                .running
        );
        let path = root.path().join("private.sock");
        let listener = bind_listener(&path, unsafe { libc::geteuid() }).unwrap();
        let private_owner = owner.clone();
        let private =
            std::thread::spawn(move || serve_dispatcher_one(&listener, &private_owner, true));
        let (mut client, server) = UnixStream::pair().unwrap();
        configure_stream(&client).unwrap();
        configure_stream(&server).unwrap();
        let peer = peer_identity(&server).unwrap();
        let (release, released) = mpsc::channel();
        let lifecycle_owner = owner.clone();
        let lifecycle = std::thread::spawn(move || {
            let mut gated = PublishedResponseGate {
                stream: server,
                release: Some(released),
            };
            serve_dispatcher_stream(
                &mut gated,
                &peer,
                &lifecycle_owner,
                false,
                Path::new("/unused"),
            )
        });
        client
            .write_all(
                &d::encode_frame(&d::DispatcherRequest::Version {
                    contract_version: 1,
                })
                .unwrap(),
            )
            .unwrap();
        let lifecycle_response = d::read_frame(&mut client, d::MAX_DISPATCHER_FRAME);
        // Receiving the complete frame proves publication, while the first
        // server's write cannot return until this test releases its channel.
        let mut request = UnixStream::connect(&path).unwrap();
        configure_stream(&request).unwrap();
        let private_response = request
            .write_all(&encode_request(&Request::version()).unwrap())
            .and_then(|()| d::read_frame(&mut request, MAX_FRAME_SIZE));
        // Release and join even on the expected RED busy/EOF path.
        let _ = release.send(());
        let lifecycle_result = lifecycle.join();
        let private_result = private.join();
        let stopped = owner.lock().unwrap().handle(
            d::DispatcherRequest::Stop {
                contract_version: 1,
                identity,
            },
            &mut |_, _| Err(d::blocked()),
        );
        assert!(stopped.ok && !stopped.running);
        assert!(lifecycle_response.is_ok());
        assert_eq!(lifecycle_result.unwrap(), Ok(()));
        assert_eq!(
            private_result.unwrap(),
            Ok(()),
            "completed lifecycle response must release dispatcher ownership before publication"
        );
        let response = decode_response(&private_response.unwrap()).unwrap();
        assert!(response.ok);
        assert_eq!(response.service_version.as_deref(), Some("0.2.16"));
    }
}
