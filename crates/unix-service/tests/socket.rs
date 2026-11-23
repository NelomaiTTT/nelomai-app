use nelomai_unix_service::{
    bind_listener, serve_one, ClientPolicy, ServiceError, ServiceTunnelBackend, ServiceTunnelState,
    TunnelRequestHandler, UnixSocketTransport,
};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use tempfile::tempdir;

mod support;
use support::{owned_dispatcher, owned_dispatcher_with_slots};

#[test]
fn production_dispatcher_socket_uses_verified_identity_and_rejects_foreign_peer() {
    use nelomai_contracts::dispatcher as d;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    let (target, owner) = owned_dispatcher();
    let path = target.path().join("dispatcher.sock");
    let listener = bind_listener(&path, unsafe { libc::geteuid() }).unwrap();
    let server_owner = std::sync::Arc::clone(&owner);
    let server = std::thread::spawn(move || {
        nelomai_unix_service::serve_dispatcher_one(&listener, &server_owner, false).unwrap();
        let rejection = nelomai_unix_service::serve_dispatcher_one(&listener, &server_owner, false)
            .unwrap_err();
        assert_eq!(
            rejection,
            ServiceError::BrokerRejected(d::BrokerDenial::PathMismatch)
        );
        assert_eq!(rejection.code(), "unauthorized_client");
    });
    let mut stream = UnixStream::connect(&path).unwrap();
    stream
        .write_all(
            &d::encode_frame(&d::DispatcherRequest::Version {
                contract_version: 1,
            })
            .unwrap(),
        )
        .unwrap();
    let frame = d::read_frame(&mut stream, d::MAX_DISPATCHER_FRAME).unwrap();
    let response: d::DispatcherResponse =
        serde_json::from_slice(d::frame_body(&frame, d::MAX_DISPATCHER_FRAME).unwrap()).unwrap();
    assert!(response.ok && !response.running);
    assert_eq!(
        response.identity.as_ref(),
        Some(&owner.lock().unwrap().layout.identity)
    );
    drop(stream);
    let status = std::process::Command::new("/usr/bin/python3")
        .args([
            "-c",
            "import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1]);\ntry: assert s.recv(1024) == b''\nexcept ConnectionResetError: pass",
        ])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
    server.join().unwrap();
    assert!(!target.path().join(d::ACTIVE_ENGINE_NAME).exists());
}

#[tokio::test]
async fn production_transport_stop_then_passive_poll_preserves_quiescence() {
    use nelomai_contracts::dispatcher as d;
    use nelomai_unix_service::{Request, ServiceTransport};
    let (target, owner) = owned_dispatcher();
    {
        let mut dispatcher = owner.lock().unwrap();
        let identity = dispatcher.layout.identity.clone();
        assert!(
            dispatcher
                .handle(
                    d::DispatcherRequest::Start {
                        contract_version: 1,
                        identity
                    },
                    &mut |_, _| Ok(())
                )
                .running
        );
    }
    assert!(target.path().join(d::ACTIVE_ENGINE_NAME).exists());
    let path = target.path().join("dispatcher.sock");
    let listener = bind_listener(&path, unsafe { libc::geteuid() }).unwrap();
    let server_owner = owner.clone();
    #[cfg(target_os = "linux")]
    let private_thread = {
        let private = bind_listener(&target.path().join("private.sock"), unsafe {
            libc::geteuid()
        })
        .unwrap();
        let private_owner = owner.clone();
        std::thread::spawn(move || {
            nelomai_unix_service::serve_dispatcher_one(&private, &private_owner, true)
        })
    };
    // Stop performs version + stop; each passive poll only reads version.
    // Capability Version is no longer passive: it may bring up a verified engine.
    let server = std::thread::spawn(move || {
        for _ in 0..4 {
            nelomai_unix_service::serve_dispatcher_one(&listener, &server_owner, false).unwrap();
        }
    });
    let transport = UnixSocketTransport::with_dispatcher(target.path().join("private.sock"), path);
    assert_eq!(
        transport.exchange(Request::stop()).await.unwrap().state,
        Some(ServiceTunnelState::Stopped)
    );
    assert!(!target.path().join(d::ACTIVE_ENGINE_NAME).exists());
    // Exercise the actual controller contract used by the app's periodic poll.
    use nelomai_client_tunnel::{TunnelController, TunnelStatus};
    let controller = nelomai_unix_service::UnixTunnelController::new(transport);
    assert_eq!(controller.status().await.unwrap(), TunnelStatus::Stopped);
    #[cfg(target_os = "linux")]
    {
        assert!(controller
            .diagnostics()
            .await
            .unwrap()
            .contains("source=persisted"));
        private_thread.join().unwrap().unwrap();
    }
    #[cfg(not(target_os = "linux"))]
    assert!(controller.diagnostics().await.is_err());
    server.join().unwrap();
    assert!(!target.path().join(d::ACTIVE_ENGINE_NAME).exists());
    assert!(
        !owner
            .lock()
            .unwrap()
            .handle(
                d::DispatcherRequest::Status {
                    contract_version: 1
                },
                &mut |_, _| Ok(())
            )
            .running
    );
}

#[test]
fn real_engine_channel_keeps_diagnostics_rebind_and_eof_cleanup() {
    use nelomai_contracts::dispatcher as d;
    use nelomai_unix_service::{decode_response, encode_request, run_engine_channel, Request};
    let mut input = encode_request(&Request::diagnostics()).unwrap();
    input.extend(encode_request(&Request::rebind_udp()).unwrap());
    let mut output = Vec::new();
    let mut handler = TunnelRequestHandler::new(MemoryBackend::default(), "0.2.16");
    run_engine_channel(&mut input.as_slice(), &mut output, &mut handler).unwrap();
    let mut bytes = output.as_slice();
    let diagnostics =
        decode_response(&d::read_frame(&mut bytes, d::MAX_ENGINE_FRAME).unwrap()).unwrap();
    assert_eq!(
        diagnostics.diagnostics.as_deref(),
        Some("private engine diagnostics")
    );
    let rebind = decode_response(&d::read_frame(&mut bytes, d::MAX_ENGINE_FRAME).unwrap()).unwrap();
    assert_eq!(rebind.state, Some(ServiceTunnelState::Running));
    assert_eq!(
        handler.backend().state,
        ServiceTunnelState::Stopped,
        "EOF must clean up the tunnel"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn cancelled_stall_rebind_never_reaches_native_engine() {
    use nelomai_client_tunnel::{StallRebindGuard, TunnelController};
    use nelomai_contracts::dispatcher as d;
    use nelomai_unix_service::UnixTunnelController;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    for drop_future in [true, false] {
        let (root, owner) = owned_dispatcher();
        let dispatcher_path = root.path().join("life.sock");
        let native_path = root.path().join("test.sock");
        let uid = unsafe { libc::geteuid() };
        let dispatcher = bind_listener(&dispatcher_path, uid).unwrap();
        let native = bind_listener(&native_path, uid).unwrap();
        let identity = owner.lock().unwrap().layout.identity.clone();
        let binding = d::CommonEngineBinding::default();
        binding.bind(identity.clone()).unwrap();
        let (version_seen, seen) = tokio::sync::oneshot::channel();
        let (allow_reply, held) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = dispatcher.accept().unwrap();
            let request = d::read_frame(&mut socket, d::MAX_DISPATCHER_FRAME).unwrap();
            assert!(matches!(
                serde_json::from_slice(d::frame_body(&request, d::MAX_DISPATCHER_FRAME).unwrap())
                    .unwrap(),
                d::DispatcherRequest::Version {
                    contract_version: 1
                }
            ));
            version_seen.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(4)).unwrap();
            socket
                .write_all(
                    &d::encode_frame(&d::DispatcherResponse::success(identity, true)).unwrap(),
                )
                .unwrap();
        });
        let controller = UnixTunnelController::new(
            UnixSocketTransport::with_dispatcher(native_path, dispatcher_path).for_common(binding),
        );
        let current = Arc::new(AtomicBool::new(true));
        let still_current = Arc::clone(&current);
        let guard = StallRebindGuard::new(Instant::now() + Duration::from_secs(15), move || {
            still_current.load(Ordering::SeqCst)
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let rebind = tokio::spawn(async move { controller.rebind_udp_for_stall(guard).await });
            tokio::time::timeout(Duration::from_secs(3), seen)
                .await
                .unwrap()
                .unwrap();
            if drop_future {
                rebind.abort();
                assert!(rebind.await.unwrap_err().is_cancelled());
                allow_reply.send(()).unwrap();
            } else {
                current.store(false, Ordering::SeqCst);
                allow_reply.send(()).unwrap();
                assert!(rebind.await.unwrap().is_err());
            }
        });
        server.join().unwrap();
        // Drain any detached blocking exchange before checking the native socket.
        native.set_nonblocking(true).unwrap();
        drop(runtime);
        assert!(matches!(
            native.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn cancelled_stall_start_during_dispatcher_version_never_dispatches_start() {
    assert_cancelled_stall_start(false);
}

#[cfg(target_os = "macos")]
#[test]
fn cancelled_stall_start_during_dispatcher_start_never_contacts_native_engine() {
    assert_cancelled_stall_start(true);
}

#[cfg(target_os = "macos")]
fn assert_cancelled_stall_start(delay_lifecycle_start: bool) {
    use nelomai_client_tunnel::{
        TunnelConfiguration, TunnelController, TunnelError, TunnelStartRequest, WakeDispatchGuard,
        WAKE_DISPATCH_DEFERRED,
    };
    use nelomai_contracts::dispatcher as d;
    use nelomai_unix_service::UnixTunnelController;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    for drop_future in [false, true] {
        let (root, owner) = owned_dispatcher();
        let dispatcher_path = root.path().join("life.sock");
        let native_path = root.path().join("test.sock");
        let uid = unsafe { libc::geteuid() };
        let dispatcher = bind_listener(&dispatcher_path, uid).unwrap();
        let native = bind_listener(&native_path, uid).unwrap();
        let identity = owner.lock().unwrap().layout.identity.clone();
        let binding = d::CommonEngineBinding::default();
        binding.bind(identity.clone()).unwrap();
        let (request_seen, seen) = tokio::sync::oneshot::channel();
        let (allow_reply, held) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let read_request = |socket: &mut std::os::unix::net::UnixStream| {
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let frame = d::read_frame(socket, d::MAX_DISPATCHER_FRAME).unwrap();
                serde_json::from_slice::<d::DispatcherRequest>(
                    d::frame_body(&frame, d::MAX_DISPATCHER_FRAME).unwrap(),
                )
                .unwrap()
            };
            let mut reply_to = dispatcher.accept().unwrap().0;
            assert!(matches!(
                read_request(&mut reply_to),
                d::DispatcherRequest::Version {
                    contract_version: 1
                }
            ));
            if delay_lifecycle_start {
                reply_to
                    .write_all(
                        &d::encode_frame(&d::DispatcherResponse::success(identity.clone(), false))
                            .unwrap(),
                    )
                    .unwrap();
                reply_to = dispatcher.accept().unwrap().0;
                assert!(matches!(
                    read_request(&mut reply_to),
                    d::DispatcherRequest::Start { contract_version: 1, identity: requested }
                        if requested == identity
                ));
            }
            request_seen.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(4)).unwrap();
            reply_to
                .write_all(
                    &d::encode_frame(&d::DispatcherResponse::success(
                        identity,
                        delay_lifecycle_start,
                    ))
                    .unwrap(),
                )
                .unwrap();
            dispatcher
        });

        let controller = UnixTunnelController::new(
            UnixSocketTransport::with_dispatcher(native_path, dispatcher_path).for_common(binding),
        );
        let current = Arc::new(AtomicBool::new(true));
        let still_current = Arc::clone(&current);
        let guard = WakeDispatchGuard::new(None, move || still_current.load(Ordering::SeqCst));
        let request = TunnelStartRequest::full_tunnel(TunnelConfiguration::new(
            "[Interface]\nAddress = 10.0.0.2/32\n".into(),
        ));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let start = tokio::spawn(async move { controller.start_guarded(request, guard).await });
            tokio::time::timeout(Duration::from_secs(3), seen)
                .await
                .unwrap()
                .unwrap();
            if drop_future {
                start.abort();
                assert!(start.await.unwrap_err().is_cancelled());
                allow_reply.send(()).unwrap();
            } else {
                current.store(false, Ordering::SeqCst);
                allow_reply.send(()).unwrap();
                assert!(matches!(
                    start.await.unwrap(),
                    Err(TunnelError::Backend(code)) if code == WAKE_DISPATCH_DEFERRED
                ));
            }
        });
        let dispatcher = server.join().unwrap();
        // A dropped async caller can leave a blocking worker completing its lookup.
        drop(runtime);
        dispatcher.set_nonblocking(true).unwrap();
        native.set_nonblocking(true).unwrap();
        assert!(matches!(
            dispatcher.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert!(matches!(
            native.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn current_stall_start_dispatches_one_ordinary_request() {
    use nelomai_client_tunnel::{
        TunnelConfiguration, TunnelController, TunnelError, TunnelStartRequest, WakeDispatchGuard,
        WAKE_DISPATCH_DEFERRED,
    };
    use nelomai_contracts::dispatcher as d;
    use nelomai_unix_service::{
        decode_request, encode_response, Request, Response, UnixTunnelController,
    };
    use std::io::Write;
    use std::time::Duration;

    let root = tempdir().unwrap();
    let path = root.path().join("test.sock");
    let native = bind_listener(&path, unsafe { libc::geteuid() }).unwrap();
    let controller = UnixTunnelController::new(UnixSocketTransport::new(path));
    let request = || {
        let mut request = TunnelStartRequest::full_tunnel(TunnelConfiguration::new(
            "[Interface]\nAddress = 10.0.0.2/32\nDNS = 192.0.2.1\n".into(),
        ));
        request.options.dns_servers = vec!["192.0.2.2".parse().unwrap()];
        request
    };
    assert!(matches!(
        controller
            .start_guarded(request(), WakeDispatchGuard::new(None, || false))
            .await,
        Err(TunnelError::Backend(code)) if code == WAKE_DISPATCH_DEFERRED
    ));
    native.set_nonblocking(true).unwrap();
    assert!(matches!(
        native.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    native.set_nonblocking(false).unwrap();
    let helper = std::thread::spawn(move || {
        let (mut stream, _) = native.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let frame = d::read_frame(&mut stream, d::MAX_ENGINE_FRAME).unwrap();
        assert!(matches!(
            decode_request(&frame).unwrap(),
            Request::Start { configuration, .. }
                if configuration.as_str() == "[Interface]\nAddress = 10.0.0.2/32\nDNS = 192.0.2.2\n"
        ));
        stream
            .write_all(
                &encode_response(&Response::success(Some(ServiceTunnelState::Running))).unwrap(),
            )
            .unwrap();
        native
    });
    controller
        .start_guarded(request(), WakeDispatchGuard::new(None, || true))
        .await
        .unwrap();
    let native = helper.join().unwrap();
    native.set_nonblocking(true).unwrap();
    assert!(matches!(
        native.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[tokio::test]
async fn common_bound_transport_launches_signed_stable_through_real_dispatcher_socket() {
    use nelomai_contracts::{dispatcher as d, RuntimeSlot};
    use nelomai_unix_service::{Request, ServiceTransport};
    let (root, owner) = owned_dispatcher_with_slots(true);
    let stable = owner
        .lock()
        .unwrap()
        .installation
        .load_slot(RuntimeSlot::Stable)
        .unwrap()
        .identity;
    let lifecycle_path = root.path().join("lifecycle.sock");
    let private_path = root.path().join("private.sock");
    let lifecycle = bind_listener(&lifecycle_path, unsafe { libc::geteuid() }).unwrap();
    let private = bind_listener(&private_path, unsafe { libc::geteuid() }).unwrap();
    let lifecycle_owner = owner.clone();
    let lifecycle_thread = std::thread::spawn(move || {
        // Pre-bind stop(2), bound start(2), bound private version(1), stop(2).
        for _ in 0..7 {
            nelomai_unix_service::serve_dispatcher_one(&lifecycle, &lifecycle_owner, false)
                .unwrap();
        }
    });
    let private_owner = owner.clone();
    let private_thread = std::thread::spawn(move || {
        for _ in 0..2 {
            nelomai_unix_service::serve_dispatcher_one(&private, &private_owner, true).unwrap();
        }
    });
    let binding = d::CommonEngineBinding::default();
    let transport = UnixSocketTransport::with_dispatcher(private_path, lifecycle_path)
        .for_common(binding.clone());
    let retained = transport.clone();
    assert!(retained
        .exchange(Request::start("synthetic".into()))
        .await
        .is_err());
    transport.exchange(Request::stop()).await.unwrap();
    binding.bind(stable.clone()).unwrap();
    assert!(
        retained
            .exchange(Request::start("synthetic".into()))
            .await
            .unwrap()
            .ok
    );
    assert_eq!(owner.lock().unwrap().layout.identity, stable);
    assert_eq!(
        retained
            .exchange(Request::version())
            .await
            .unwrap()
            .service_version
            .as_deref(),
        Some("0.2.16")
    );
    transport.exchange(Request::stop()).await.unwrap();
    lifecycle_thread.join().unwrap();
    private_thread.join().unwrap();
    assert!(!root.path().join(d::ACTIVE_ENGINE_NAME).exists());
}

#[test]
fn malformed_private_json_gets_a_bounded_error_without_abandoning_the_engine() {
    use nelomai_contracts::dispatcher as d;
    let mut input = vec![1, 0, 0, 0, b'{'];
    input.extend(
        nelomai_unix_service::encode_request(&nelomai_unix_service::Request::status()).unwrap(),
    );
    let mut handler = TunnelRequestHandler::new(
        MemoryBackend {
            state: ServiceTunnelState::Running,
        },
        "test",
    );
    let mut output = Vec::new();
    nelomai_unix_service::run_engine_channel(&mut input.as_slice(), &mut output, &mut handler)
        .unwrap();
    let mut bytes = output.as_slice();
    let error = nelomai_unix_service::decode_response(
        &d::read_frame(&mut bytes, d::MAX_ENGINE_FRAME).unwrap(),
    )
    .unwrap();
    assert!(!error.ok);
    let status = nelomai_unix_service::decode_response(
        &d::read_frame(&mut bytes, d::MAX_ENGINE_FRAME).unwrap(),
    )
    .unwrap();
    assert_eq!(status.state, Some(ServiceTunnelState::Running));
}

#[test]
fn same_uid_foreign_executable_is_rejected_before_decode() {
    let directory = tempdir().unwrap();
    let socket_path = directory.path().join("peer.sock");
    let uid = unsafe { libc::geteuid() };
    let listener = bind_listener(&socket_path, uid).unwrap();
    let server = std::thread::spawn(move || {
        let policy = ClientPolicy {
            owner_uid: uid,
            installed_client_path: fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
        };
        let mut handler = TunnelRequestHandler::new(MemoryBackend::default(), "test");
        serve_one(&listener, &policy, &mut handler)
    });
    // A distinct real executable with the same UID, just like the runtime child.
    // Invalid JSON is intentional: authorization must happen before decoding it.
    let result = std::process::Command::new("/usr/bin/python3")
        .args(["-c", "import errno,socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]);\ntry:\n s.sendall(b'\\x01\\x00\\x00\\x00{')\n s.recv(1024)\nexcept OSError as error:\n if error.errno not in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN): raise\nfinally: s.close()"])
        .arg(socket_path)
        .status()
        .unwrap();
    assert!(result.success());
    assert_eq!(
        server.join().unwrap(),
        Err(ServiceError::UnauthorizedClient)
    );
}

#[derive(Default)]
struct MemoryBackend {
    state: ServiceTunnelState,
}

impl ServiceTunnelBackend for MemoryBackend {
    fn start(
        &mut self,
        _configuration: &nelomai_unix_service::ParsedConfiguration,
        _options: &nelomai_client_tunnel::DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        self.state = ServiceTunnelState::Running;
        Ok(self.state)
    }

    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.state = ServiceTunnelState::Stopped;
        Ok(self.state)
    }

    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(self.state)
    }
    fn diagnostics(&self) -> Result<String, ServiceError> {
        Ok("private engine diagnostics".into())
    }
    fn rebind_udp(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.state = ServiceTunnelState::Running;
        Ok(self.state)
    }
}

#[tokio::test]
async fn unix_socket_round_trip_is_owner_only_and_bounded() {
    let directory = tempdir().expect("create temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("protect temporary directory");
    let socket_path = directory.path().join("tunnel.sock");
    let uid = unsafe { libc::geteuid() };
    let listener = bind_listener(&socket_path, uid).expect("bind helper socket");
    let metadata = fs::metadata(&socket_path).expect("read socket metadata");

    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), uid);

    let server = std::thread::spawn(move || {
        let policy = ClientPolicy {
            owner_uid: uid,
            installed_client_path: fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
        };
        let mut handler = TunnelRequestHandler::new(MemoryBackend::default(), "test");
        serve_one(&listener, &policy, &mut handler).expect("serve request");
    });

    let transport = UnixSocketTransport::new(socket_path);
    let response = nelomai_unix_service::ServiceTransport::exchange(
        &transport,
        nelomai_unix_service::Request::status(),
    )
    .await
    .expect("exchange request");

    assert_eq!(response.state, Some(ServiceTunnelState::Stopped));
    server.join().expect("join helper thread");
}

#[tokio::test]
async fn timed_out_dispatcher_stop_is_drained_before_retry_ack_and_new_start() {
    use nelomai_contracts::dispatcher as d;
    use nelomai_unix_service::{Request, ServiceTransport};
    use std::time::Duration;
    let (root, owner) = owned_dispatcher();
    {
        let mut dispatcher = owner.lock().unwrap();
        let identity = dispatcher.layout.identity.clone();
        assert!(
            dispatcher
                .handle(
                    d::DispatcherRequest::Start {
                        contract_version: 1,
                        identity
                    },
                    &mut |_, _| Ok(())
                )
                .running
        );
    }
    let hold = root.path().join("hold-test-stop");
    fs::write(&hold, b"test gate").unwrap();
    let entered = root.path().join("test-stop-entered");
    let lifecycle_path = root.path().join("lifecycle.sock");
    let private_path = root.path().join("private.sock");
    let listener = bind_listener(&lifecycle_path, unsafe { libc::geteuid() }).unwrap();
    let private = bind_listener(&private_path, unsafe { libc::geteuid() }).unwrap();
    let server_owner = owner.clone();
    let server = std::thread::spawn(move || {
        // Each Stop and Start performs Version followed by the mutation.
        // The first Stop finishes after its client has closed the socket.
        for _ in 0..6 {
            let _ = nelomai_unix_service::serve_dispatcher_one(&listener, &server_owner, false);
        }
    });
    let private_owner = owner.clone();
    let private_server = std::thread::spawn(move || {
        nelomai_unix_service::serve_dispatcher_one(&private, &private_owner, true).unwrap();
    });
    let transport = UnixSocketTransport::with_dispatcher(private_path, lifecycle_path);
    let first = {
        let t = transport.clone();
        tokio::spawn(async move { t.exchange(Request::stop()).await })
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        while !entered.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(7), first)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err(),
        ServiceError::DispatcherTimeout,
        "real socket timeout must occur while the dispatcher is still executing Stop"
    );
    assert!(root.path().join(d::ACTIVE_ENGINE_NAME).exists());
    let mut retry = {
        let t = transport.clone();
        tokio::spawn(async move { t.exchange(Request::stop()).await })
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut retry)
            .await
            .is_err(),
        "retry may not acknowledge cleanup ahead of the previous lifecycle request"
    );
    fs::remove_file(hold).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), retry)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .state,
        Some(ServiceTunnelState::Stopped)
    );
    assert!(!root.path().join(d::ACTIVE_ENGINE_NAME).exists());
    assert!(
        transport
            .exchange(Request::start("synthetic".into()))
            .await
            .unwrap()
            .ok
    );
    server.join().unwrap();
    private_server.join().unwrap();
    let mut dispatcher = owner.lock().unwrap();
    assert!(
        dispatcher
            .handle(
                d::DispatcherRequest::Status {
                    contract_version: 1
                },
                &mut |_, _| Ok(())
            )
            .running,
        "new engine survives after all earlier stops and a positive cleanup receipt"
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore = "requires a disposable macOS VM and the installed test transport binaries"]
async fn native_macos_start_fits_the_client_ipc_deadline() {
    use nelomai_client_tunnel::{
        redundancy::{
            protocol::{Command, Member},
            SessionScope, Slot,
        },
        DesktopTunnelOptions, TunnelConfiguration,
    };
    use nelomai_contracts::RuntimeSlot;
    use nelomai_unix_service::{
        member_network::{actor::CompositeBackend, runtime::NativePairFactory},
        PlatformBackend, Request, ServiceTransport, PROTOCOL_VERSION,
    };

    assert_eq!(unsafe { libc::geteuid() }, 0);
    let model = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "hw.model"])
        .output()
        .unwrap();
    assert!(model.status.success() && model.stdout.starts_with(b"VirtualMac"));
    let binaries = std::path::PathBuf::from(std::env::var_os("NELOMAI_MAC_QA_BINARIES").unwrap());

    let configuration = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32, fd12:ca6e::2/128\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 198.19.237.60:51820\n";
    // Individual bypasses distributed across the full-tunnel address space
    // reproduce the large route plan without reaching those destinations.
    let options = DesktopTunnelOptions {
        excluded_ipv4_cidrs: (0..40)
            .map(|i| format!("{}.1.2.3/32", 11 + 4 * i))
            .collect(),
        exclude_local_networks: true,
        policy_hash: Some("sha256:test".into()),
    };
    let scope = SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 1,
        session_id: "11111111-1111-4111-8111-111111111111".into(),
        connection_generation: 1,
    };
    let command = |request| Request::Redundant {
        protocol_version: PROTOCOL_VERSION,
        request,
    };

    for reserve in [false, true] {
        let root = tempdir().unwrap();
        let runtime = root.path().join("runtime");
        let pair_root = root.path().join("pair");
        fs::create_dir(&runtime).unwrap();
        fs::create_dir(&pair_root).unwrap();
        fs::set_permissions(&pair_root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.path().join("tunnel.sock");
        let listener = bind_listener(&socket, 0).unwrap();
        let server = std::thread::spawn({
            let binaries = binaries.clone();
            move || {
                let platform = PlatformBackend::new(
                    binaries.join("wireguard-go"),
                    binaries.join("amneziawg-go"),
                    runtime,
                )
                .unwrap();
                let factory =
                    NativePairFactory::new(&pair_root, RuntimeSlot::Latest, &binaries).unwrap();
                let backend =
                    CompositeBackend::new(RuntimeSlot::Latest, platform, factory).unwrap();
                let mut handler = TunnelRequestHandler::new(backend, env!("CARGO_PKG_VERSION"));
                let policy = ClientPolicy {
                    owner_uid: 0,
                    installed_client_path: std::env::current_exe().unwrap().canonicalize().unwrap(),
                };
                let calls = if reserve { 4 } else { 3 };
                // Process Stop before asserting the Start result, including
                // when the client gives up before the server completes.
                (0..calls)
                    .map(|_| serve_one(&listener, &policy, &mut handler))
                    .collect::<Vec<_>>()
            }
        });
        let (start, stop) = if reserve {
            let member = Member {
                slot: Slot::A,
                lease_id: "22222222-2222-4222-8222-222222222222".into(),
                configuration: TunnelConfiguration::new(configuration.into()),
                probe: serde_json::from_value(serde_json::json!({
                    "kind": "dns_a",
                    "target_ipv4": "198.19.237.100",
                    "query_name": "example.com",
                    "timeout_ms": 2000,
                }))
                .unwrap(),
            };
            (
                command(Command::Start {
                    scope: scope.clone(),
                    primary: member,
                    role_generation: 1,
                    membership_generation: 1,
                    warm_stop_v1: true,
                    options: options.clone(),
                }),
                command(Command::Stop {
                    scope: scope.clone(),
                }),
            )
        } else {
            (
                Request::start_with_options(configuration.into(), options.clone()),
                Request::stop_if_unowned(),
            )
        };
        let transport = UnixSocketTransport::new(socket);
        let started_at = std::time::Instant::now();
        let started = transport
            .exchange_wake_mutation(
                start,
                nelomai_client_tunnel::WakeDispatchGuard::new(None, || true),
            )
            .await;
        let start_ms = started_at.elapsed().as_millis();
        let guarded_stop = |allowed: bool| {
            transport.exchange_wake_mutation(
                Request::stop_if_unowned(),
                nelomai_client_tunnel::WakeDispatchGuard::new(None, move || allowed),
            )
        };
        let deferred = guarded_stop(false).await;
        let foreign_stop = if reserve {
            Some(guarded_stop(true).await)
        } else {
            None
        };
        let still_live = transport.exchange(Request::status()).await;
        let stopped = if reserve {
            transport.exchange(stop).await
        } else {
            transport
                .exchange_wake_mutation(
                    stop,
                    nelomai_client_tunnel::WakeDispatchGuard::new(None, || true),
                )
                .await
        };
        let service = server.join().unwrap();
        let started = started.expect("native Start must answer before the client IPC deadline");
        assert!(
            started.error_code.is_none(),
            "Start returned {:?}",
            started.error_code
        );
        assert!(
            service.iter().all(Result::is_ok),
            "native responses: {service:?}"
        );
        assert!(matches!(deferred, Err(ServiceError::WakeDispatchDeferred)));
        if let Some(result) = foreign_stop {
            assert!(
                result.unwrap().error_code.is_some(),
                "singleton Stop must preserve a pair"
            );
        }
        let still_live = still_live.unwrap();
        assert!(matches!(
            still_live.state,
            Some(ServiceTunnelState::Starting | ServiceTunnelState::Running)
        ));
        assert_eq!(still_live.redundancy.is_some(), reserve);
        let stopped = stopped.unwrap();
        assert!(
            stopped.error_code.is_none(),
            "Stop returned {:?}",
            stopped.error_code
        );
        eprintln!("reserve={reserve} start_ms={start_ms}");
    }
}
