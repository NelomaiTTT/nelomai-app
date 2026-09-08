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
        assert_eq!(
            nelomai_unix_service::serve_dispatcher_one(&listener, &server_owner, false),
            Err(ServiceError::UnauthorizedClient)
        );
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
    let status = std::process::Command::new("/usr/bin/python3").args(["-c", "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]);\ntry: s.recv(1024)\nexcept ConnectionResetError: pass"] ).arg(path).status().unwrap();
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
    // Stop performs version + stop; each passive poll only reads version.
    let server = std::thread::spawn(move || {
        for _ in 0..5 {
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
    assert_eq!(controller.service_version().await.unwrap(), "0.2.16");
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
        .args(["-c", "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b'\\x01\\x00\\x00\\x00{');\ntry: s.recv(1024)\nexcept ConnectionResetError: pass\ns.close()"])
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
