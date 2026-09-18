//! Supplemental exact-byte stable launch, NOT production two-slot/tunnel acceptance.
//! Runs only in a disposable Linux network namespace with loopback alone. The
//! ordinary installed common/ProcessDispatcher check is a separate adapter run.
#[cfg(unix)]
mod harness {
    use nelomai_client_container::{
        desktop::{read_native_frame, write_native_frame, VerifiedRuntime},
        host::{CommonHost, HostNativePorts},
        ipc::{BackgroundAction, PrivateBackgroundDispatcher},
        BrokerError, LocalAuthStop, NativeAuthFailure, NativeAuthRequest, RuntimeClientProfile,
        SlotSelectionV1, UnavailableRuntimeForceStop,
    };
    use nelomai_client_storage::{ContainerOwnerLock, SystemRecordFactory};
    use nelomai_contracts::{dispatcher, RuntimeSlot};
    use nelomai_unix_service::{
        run_engine_channel, ParsedConfiguration, ServiceError, ServiceTunnelBackend,
        ServiceTunnelState, TunnelRequestHandler,
    };
    use std::{
        fs, io,
        io::Write,
        os::unix::net::UnixStream,
        path::{Path, PathBuf},
        process::Command,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    /// Only external native effects are replaced. Start never claims a tunnel.
    struct NoPhysicalTunnel;
    impl ServiceTunnelBackend for NoPhysicalTunnel {
        fn start(
            &mut self,
            _: &ParsedConfiguration,
            _: &nelomai_client_tunnel::DesktopTunnelOptions,
        ) -> Result<ServiceTunnelState, ServiceError> {
            Err(ServiceError::Backend("physical_tunnel_UNRUN".into()))
        }
        fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
            Ok(ServiceTunnelState::Stopped)
        }
        fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
            Ok(ServiceTunnelState::Stopped)
        }
    }
    #[async_trait::async_trait]
    impl LocalAuthStop for NoPhysicalTunnel {
        async fn stop_local(&self) -> Result<(), BrokerError> {
            Ok(())
        }
    }
    #[async_trait::async_trait]
    impl PrivateBackgroundDispatcher for NoPhysicalTunnel {
        async fn prepare_revocation(&self, _: u64) -> Result<(), BrokerError> {
            Err(BrokerError::AccessUnavailable)
        }
        async fn dispatch(
            &self,
            _: NativeAuthRequest,
            _: BackgroundAction,
        ) -> Result<Option<nelomai_client_api::TokenResponse>, NativeAuthFailure> {
            Err(NativeAuthFailure::NotIssued)
        }
    }

    fn local_panel(value: &str) -> io::Result<()> {
        let port = value
            .strip_prefix("http://127.0.0.1:")
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|port| *port > 0);
        if port.is_none() {
            return Err(io::Error::other("isolated loopback panel URL required"));
        }
        Ok(())
    }

    fn open(
        data: &Path,
        resources: &Path,
        key: &[u8],
        panel: &str,
    ) -> Result<CommonHost, Box<dyn std::error::Error>> {
        Ok(CommonHost::open(
            data,
            resources,
            Some(key),
            "linux",
            "x86_64",
            || SystemRecordFactory::new("primary", Some(data.join("credentials"))),
            nelomai_client_api::ClientApi::new(panel)?,
            RuntimeClientProfile {
                platform: nelomai_contracts::Platform::Linux,
                platform_version: None,
                architecture: "x86_64".into(),
            },
            HostNativePorts {
                stop: Arc::new(NoPhysicalTunnel),
                force: Arc::new(UnavailableRuntimeForceStop),
                background: Arc::new(NoPhysicalTunnel),
                updater: None,
                storage: None,
                relaunch: None,
            },
        )?)
    }

    fn native_adapter(
        mut native: UnixStream,
        polls: Arc<AtomicUsize>,
        requests: Arc<AtomicUsize>,
    ) -> io::Result<()> {
        let (mut peer, mut engine) = UnixStream::pair()?;
        let mut engine_writer = engine.try_clone()?;
        std::thread::spawn(move || {
            run_engine_channel(
                &mut engine,
                &mut engine_writer,
                &mut TunnelRequestHandler::new(NoPhysicalTunnel, "0.2.16"),
            )
        });
        native.set_read_timeout(Some(Duration::from_secs(30)))?;
        loop {
            let (tag, body) = match read_native_frame(&mut native) {
                Ok(frame) => frame,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            };
            let reply = if tag == 1 {
                requests.fetch_add(1, Ordering::SeqCst);
                peer.write_all(&(body.len() as u32).to_le_bytes())?;
                peer.write_all(&body)?;
                let frame = dispatcher::read_frame(&mut peer, dispatcher::MAX_ENGINE_FRAME)?;
                dispatcher::frame_body(&frame, dispatcher::MAX_ENGINE_FRAME)?.to_vec()
            } else if tag == 2 {
                let command: serde_json::Value = serde_json::from_slice(&body)?;
                match command.get("command").and_then(|value| value.as_str()) {
                    Some("prepare") | Some("exit") => br#"{"result":"done"}"#.to_vec(),
                    Some("poll") => {
                        polls.fetch_add(1, Ordering::SeqCst);
                        br#"{"result":"actions","actions":[]}"#.to_vec()
                    }
                    _ => return Err(io::Error::other("unsupported supplemental native command")),
                }
            } else {
                return Err(io::Error::other("unexpected native channel tag"));
            };
            write_native_frame(&mut native, tag, &reply)?;
        }
    }

    #[tokio::main]
    pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.len() != 3 || !cfg!(target_os = "linux") {
            return Err("usage (isolated Linux only): linux-runtime-acceptance RESOURCES RAW_PUBLIC_KEY LOOPBACK_PANEL_URL".into());
        }
        let resources = PathBuf::from(&args[0]);
        let key = fs::read(&args[1])?;
        let panel = args[2].to_str().ok_or("invalid panel URL")?;
        local_panel(panel)?;
        let interfaces: Vec<_> = fs::read_dir("/sys/class/net")?.collect::<Result<_, _>>()?;
        if interfaces.len() != 1 || interfaces[0].file_name() != "lo" {
            return Err(
                "external networking must be disabled; use the disposable adapter container".into(),
            );
        }
        let owner = unsafe { libc::geteuid() };
        if owner == 0 {
            return Err("supplemental runtime must run as a disposable unprivileged user".into());
        }
        let verified =
            VerifiedRuntime::open(&resources, &key, RuntimeSlot::Stable, "linux", "x86_64", 0)?;
        let expected_executable = verified.executable().to_owned();
        let data = tempfile::tempdir()?;
        // Initialize fresh real protected records, then select stable under the
        // same public owner-lock contract. Never touch an existing user's data.
        drop(open(data.path(), &resources, &key, panel)?);
        {
            let _owner = ContainerOwnerLock::try_acquire(data.path())?;
            fs::write(
                data.path().join("common/runtime-selection-v1.json"),
                SlotSelectionV1 {
                    container_version: "0.2.16".into(),
                    selected_slot: RuntimeSlot::Stable,
                    pending_slot: None,
                }
                .to_persisted_bytes()?,
            )?;
        }
        let host = open(data.path(), &resources, &key, panel)?;
        if host.selection().await?.target.runtime_slot != RuntimeSlot::Stable {
            return Err("stable selection failed".into());
        }
        let mut child = host.launch_desktop(0).await?;
        if child.kernel_executable()? != expected_executable {
            return Err("executed candidate identity changed".into());
        }
        let polls = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let native = child.take_native()?;
        let adapter = {
            let polls = polls.clone();
            let requests = requests.clone();
            std::thread::spawn(move || native_adapter(native, polls, requests))
        };
        // The probe reads the real AT-SPI WebView tree for this exact child PID;
        // it is installed from the pinned source in the read-only test image.
        let ui = Command::new("python3")
            .args([
                "/opt/nelomai-acceptance/check-runtime-webview.py",
                "--pid",
                &child.id().to_string(),
            ])
            .status()?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while (polls.load(Ordering::SeqCst) < 2 || requests.load(Ordering::SeqCst) == 0)
            && Instant::now() < deadline
        {
            if child.exited()? {
                return Err("candidate runtime exited before evidence".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        child.terminate()?;
        adapter.join().map_err(|_| "native adapter panicked")??;
        if !ui.success() || polls.load(Ordering::SeqCst) < 2 || requests.load(Ordering::SeqCst) == 0
        {
            return Err("WebView or real private native/engine channel exercise failed".into());
        }
        VerifiedRuntime::open(&resources, &key, RuntimeSlot::Stable, "linux", "x86_64", 0)?;
        println!(
            "{}",
            serde_json::json!({"scope":"supplemental-common-contract", "stable_executable_sha256":dispatcher::file_digest(&expected_executable)?,
            "webview":"observed", "native_polls":polls.load(Ordering::SeqCst), "engine_requests":requests.load(Ordering::SeqCst),
            "physical_tunnel":"UNRUN", "stable_production_dispatcher":"NOT_IMPLEMENTED", "full_candidate_acceptance":"UNRUN"})
        );
        Ok(())
    }

    #[test]
    fn rejects_production_or_non_loopback_panel_endpoints() {
        assert!(local_panel("http://127.0.0.1:56590").is_ok());
        for value in [
            "https://nelomai.ru",
            "http://example.test:80",
            "http://127.0.0.1:0",
            "http://127.0.0.1:80/path",
        ] {
            assert!(local_panel(value).is_err());
        }
    }

    #[test]
    fn real_engine_wire_reports_version_and_stopped_without_claiming_tunnel() {
        let mut input =
            dispatcher::encode_frame(&nelomai_unix_service::Request::version()).unwrap();
        input.extend(dispatcher::encode_frame(&nelomai_unix_service::Request::stop()).unwrap());
        let mut output = Vec::new();
        run_engine_channel(
            &mut input.as_slice(),
            &mut output,
            &mut TunnelRequestHandler::new(NoPhysicalTunnel, "0.2.16"),
        )
        .unwrap();
        let mut reader = output.as_slice();
        let first = dispatcher::read_frame(&mut reader, dispatcher::MAX_ENGINE_FRAME).unwrap();
        let response: nelomai_unix_service::Response = serde_json::from_slice(
            dispatcher::frame_body(&first, dispatcher::MAX_ENGINE_FRAME).unwrap(),
        )
        .unwrap();
        assert_eq!(response.service_version.as_deref(), Some("0.2.16"));
        let second = dispatcher::read_frame(&mut reader, dispatcher::MAX_ENGINE_FRAME).unwrap();
        let response: nelomai_unix_service::Response = serde_json::from_slice(
            dispatcher::frame_body(&second, dispatcher::MAX_ENGINE_FRAME).unwrap(),
        )
        .unwrap();
        assert_eq!(response.state, Some(ServiceTunnelState::Stopped));
        assert!(reader.is_empty());
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        harness::main()
    }
    #[cfg(not(unix))]
    {
        Err("Linux-only supplemental adapter".into())
    }
}
