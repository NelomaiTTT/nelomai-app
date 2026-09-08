//! Versioned desktop product process: UI, recovery and runtime records. Common
//! auth, installation, update and process authority are reached only privately.
use crate::*;
use nelomai_client_container::{
    desktop::{read_native_frame, write_native_frame},
    host::RuntimeBootstrapV1,
    ipc::{ChildAdmission, PrivateRuntimeAuthClient, RuntimeRecordInventory},
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    sync::{Mutex as StdMutex, OnceLock},
};
use tauri::Manager;

#[cfg(unix)]
type NativeStream = std::os::unix::net::UnixStream;
#[cfg(unix)]
type AuthStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type NativeStream = nelomai_client_container::desktop::NativeStream;
#[cfg(windows)]
type AuthStream = nelomai_client_container::ipc::windows::PrivatePipeIo;
static NATIVE: OnceLock<Arc<NativeClient>> = OnceLock::new();

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraySnapshot {
    pub disconnect: bool,
    pub traffic: String,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeAction {
    Show,
    Toggle,
    Quit,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeExitReason {
    Shutdown,
    Update,
    RuntimeSwitch,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum NativeControl {
    Prepare,
    Poll {
        presentation: TraySnapshot,
    },
    Exit {
        reason: NativeExitReason,
    },
    #[cfg(windows)]
    DefenderStatus {
        refresh: bool,
    },
    #[cfg(windows)]
    DefenderRepair,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum NativeReply {
    Done,
    Actions {
        actions: Vec<RuntimeAction>,
    },
    #[cfg(windows)]
    Defender {
        status: nelomai_windows_service::DefenderStatus,
    },
}
pub(crate) struct NativeClient {
    stream: Arc<StdMutex<Option<NativeStream>>>,
}
impl NativeClient {
    fn new(stream: NativeStream) -> io::Result<Self> {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self {
            stream: Arc::new(StdMutex::new(Some(stream))),
        })
    }
    pub async fn exchange(&self, tag: u8, body: Vec<u8>) -> io::Result<Vec<u8>> {
        let stream = self.stream.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let mut channel = stream
                .lock()
                .map_err(|_| io::Error::other("common channel unavailable"))?;
            let stream = channel
                .as_mut()
                .ok_or_else(|| io::Error::other("common channel closed"))?;
            // Engine requests have the existing 40s native watchdog. Installer
            // authorization has its existing 120s bound; auth IPC stays 10s.
            let installation =
                serde_json::from_slice::<NativeControl>(&body).is_ok_and(|request| match request {
                    NativeControl::Prepare => true,
                    #[cfg(windows)]
                    NativeControl::DefenderRepair => true,
                    _ => false,
                });
            let timeout = if tag == 1 {
                45
            } else if installation {
                130
            } else {
                10
            };
            let result = (|| {
                stream.set_read_timeout(Some(Duration::from_secs(timeout)))?;
                write_native_frame(&mut *stream, tag, &body)?;
                read_native_frame(&mut *stream)
            })();
            let (reply, body) = match result {
                Ok(reply) => reply,
                Err(error) => {
                    *channel = None;
                    return Err(error);
                }
            };
            if reply != tag && reply != 255 {
                *channel = None;
            }
            if reply != tag {
                return Err(io::Error::other("common operation failed"));
            }
            Ok(body)
        })
        .await
        .map_err(|_| io::Error::other("common channel unavailable"))?
    }
    pub async fn control(&self, request: NativeControl) -> io::Result<NativeReply> {
        let body = self.exchange(2, serde_json::to_vec(&request)?).await?;
        serde_json::from_slice(&body).map_err(Into::into)
    }
}
pub(crate) fn native() -> io::Result<Arc<NativeClient>> {
    NATIVE
        .get()
        .cloned()
        .ok_or_else(|| io::Error::other("private runtime startup required"))
}

#[cfg(all(test, unix))]
mod native_tests {
    use super::*;
    #[test]
    fn runtime_restart_is_an_explicit_full_common_exit_reason() {
        let encoded = serde_json::to_value(NativeControl::Exit {
            reason: NativeExitReason::RuntimeSwitch,
        })
        .unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({"command":"exit","reason":"runtime_switch"}),
        );
    }

    #[test]
    fn malformed_reply_permanently_closes_native_channel() {
        let (client, mut peer) = NativeStream::pair().unwrap();
        let client = NativeClient::new(client).unwrap();
        let worker = std::thread::spawn(move || {
            use std::io::Write;
            read_native_frame(&mut peer).unwrap();
            peer.write_all(&[99, 0, 0, 0, 0]).unwrap();
        });
        assert!(tauri::async_runtime::block_on(client.exchange(2, b"{}".to_vec())).is_err());
        worker.join().unwrap();
        assert!(
            client.stream.lock().unwrap().is_none(),
            "a partial/invalid reply must never be reused as the next response"
        );
    }
}

#[derive(Clone)]
pub(crate) struct RemoteTransport;
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[async_trait::async_trait]
impl nelomai_unix_service::ServiceTransport for RemoteTransport {
    async fn exchange(
        &self,
        request: nelomai_unix_service::Request,
    ) -> Result<nelomai_unix_service::Response, nelomai_unix_service::ServiceError> {
        use nelomai_unix_service::*;
        let bytes = serde_json::to_vec(&request).map_err(|_| ServiceError::TruncatedFrame)?;
        let reply = native()
            .map_err(|_| ServiceError::TruncatedFrame)?
            .exchange(1, bytes)
            .await
            .map_err(|_| ServiceError::TruncatedFrame)?;
        serde_json::from_slice(&reply).map_err(|_| ServiceError::TruncatedFrame)
    }
}
#[cfg(windows)]
#[async_trait::async_trait]
impl nelomai_windows_service::ServiceTransport for RemoteTransport {
    async fn exchange(
        &self,
        request: nelomai_windows_service::Request,
    ) -> Result<nelomai_windows_service::Response, nelomai_windows_service::ServiceError> {
        use nelomai_windows_service::*;
        let bytes = serde_json::to_vec(&request).map_err(|_| ServiceError::TruncatedFrame)?;
        let reply = native()
            .map_err(|_| ServiceError::TruncatedFrame)?
            .exchange(1, bytes)
            .await
            .map_err(|_| ServiceError::TruncatedFrame)?;
        serde_json::from_slice(&reply).map_err(|_| ServiceError::TruncatedFrame)
    }
}

pub fn run() {
    let result = (|| -> Result<_, Box<dyn std::error::Error>> {
        let (mut auth, native_stream) =
            nelomai_client_container::desktop::capture_inherited_channels()?;
        #[cfg(unix)]
        let bytes = {
            use std::io::Read;
            auth.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut size = [0; 4];
            auth.read_exact(&mut size)?;
            let size = u32::from_le_bytes(size) as usize;
            if size > 65536 {
                return Err(io::Error::other("invalid runtime bootstrap").into());
            }
            let mut bytes = vec![0; size];
            auth.read_exact(&mut bytes)?;
            auth.set_read_timeout(None)?;
            bytes
        };
        #[cfg(windows)]
        let bytes = tauri::async_runtime::block_on(async {
            use tokio::io::AsyncReadExt;
            tokio::time::timeout(Duration::from_secs(10), async {
                let size = auth.read_u32_le().await? as usize;
                if size > 65536 {
                    return Err(io::Error::other("invalid runtime bootstrap"));
                }
                let mut bytes = vec![0; size];
                auth.read_exact(&mut bytes).await?;
                Ok(bytes)
            })
            .await
            .map_err(|_| io::Error::other("runtime bootstrap timeout"))?
        })?;
        let bootstrap: RuntimeBootstrapV1 = serde_json::from_slice(&bytes)?;
        bootstrap.runtime_paths()?;
        NATIVE
            .set(Arc::new(NativeClient::new(native_stream)?))
            .map_err(|_| io::Error::other("duplicate runtime bootstrap"))?;
        Ok((auth, bootstrap))
    })();
    let (auth, bootstrap) = result.unwrap_or_else(|_| std::process::exit(1));
    crate::run_product(move |app| setup_desktop(app, auth, bootstrap));
}

fn setup_desktop(
    app: &mut tauri::App,
    auth: AuthStream,
    bootstrap: RuntimeBootstrapV1,
) -> Result<(), Box<dyn std::error::Error>> {
    use nelomai_client_storage::ProtectedRecordFactory;
    let paths = bootstrap.runtime_paths()?;
    let selected = paths
        .iter()
        .find(|path| {
            path.slot() == bootstrap.target.runtime_slot
                && path.runtime_version() == bootstrap.target.runtime_version
        })
        .ok_or_else(|| io::Error::other("runtime record unavailable"))?
        .clone();
    #[cfg(target_os = "linux")]
    let fallback = Some(bootstrap.data_root.join("credentials"));
    #[cfg(not(target_os = "linux"))]
    let fallback = None;
    let records = nelomai_client_storage::SystemRecordFactory::new("primary", fallback);
    let open = |path: nelomai_client_storage::RuntimePaths| {
        RuntimeRecordOwner::new(ProtectedRuntimeStore::new(
            records.record(path.namespace()),
            path,
        ))
    };
    let retained = paths
        .into_iter()
        .filter(|path| path != &selected)
        .map(open)
        .collect();
    let record = open(selected.clone());
    let tunnel = Arc::new(platform::tunnel_controller(app.handle().clone()));
    let local = CoreLocalStop::new(tunnel.clone());
    let admission = Arc::new(ChildAdmission::new(
        bootstrap.incarnation,
        local.runtime_writer_gates(),
        Arc::new(RuntimeRecordInventory::new(record.clone(), retained)),
    ));
    #[cfg(unix)]
    auth.set_nonblocking(true)?;
    #[cfg(unix)]
    let port = tauri::async_runtime::block_on(async {
        tokio::net::UnixStream::from_std(auth).map(|stream| {
            Arc::new(PrivateRuntimeAuthClient::new(
                stream,
                admission,
                local.clone(),
            ))
        })
    })?;
    #[cfg(windows)]
    let port = tauri::async_runtime::block_on(async {
        Arc::new(PrivateRuntimeAuthClient::new(
            auth,
            admission,
            local.clone(),
        ))
    });
    let api = ClientApi::new(PANEL_BASE)?.with_app_version(&bootstrap.target.container_version)?;
    let diagnostics = Arc::new(diagnostics::AppDiagnostics::new(
        selected
            .operational_state
            .parent()
            .ok_or_else(|| io::Error::other("runtime diagnostics unavailable"))?
            .join("diagnostics"),
        resource_usage::ResourceSnapshot::capture(app.handle()),
    )?);
    let preferences = Arc::new(preferences::AppPreferenceStore::open_runtime(
        &selected.preferences,
        &bootstrap.data_root.join("preferences.json"),
    )?);
    let application = Arc::new(ClientApplication::with_split_tunnel_store_and_preflight(
        Arc::new(api),
        Arc::new(record.operational()),
        Arc::new(record.split()),
        port.clone(),
        local,
        diagnostics.clone(),
        port.clone(),
    ));
    application.set_dns_servers(preferences.get().dns_provider.servers());
    let split = Arc::new(SplitTunnelScheduler::new());
    let push = Arc::new(PushRegistrationScheduler::new());
    let metrics = Arc::new(connection_metrics::ConnectionMetricsTracker::new());
    let intent = Arc::new(connection_intent::DesktopConnectionIntent::new(
        app.handle().clone(),
        application.clone(),
        diagnostics.clone(),
    ));
    app.manage(port.clone());
    app.manage(Arc::new(runtime_control::RuntimeControls::new(
        port.clone(),
    )));
    app.manage(Arc::new(updates::NativeUpdater::new(port.clone())));
    app.manage(application.clone());
    app.manage(tunnel.clone());
    app.manage(diagnostics.clone());
    app.manage(preferences);
    app.manage(split.clone());
    app.manage(push.clone());
    app.manage(metrics.clone());
    app.manage(intent.clone());
    let handle = app.handle().clone();
    let startup_diagnostics = diagnostics.clone();
    let startup = Arc::new(runtime_startup::RuntimeStartup::new(move || {
        diagnostics.record_named("startup.runtime_ready", None, None, None);
        start_split_tunnel_scheduler(application.clone(), split);
        start_physical_network_scheduler(application.clone(), intent.clone());
        start_pending_stop_scheduler(application.clone());
        intent.spawn();
        start_connection_metrics_scheduler(
            handle.clone(),
            application.clone(),
            tunnel.clone(),
            metrics,
            diagnostics.clone(),
        );
        start_automatic_diagnostics_scheduler(
            handle.clone(),
            application.clone(),
            tunnel,
            diagnostics,
        );
        start_push_registration_scheduler(handle.clone(), application, push);
    }));
    app.manage(startup.clone());
    tauri::async_runtime::spawn(async move {
        let _ = startup
            .recover(|| async { runtime_startup::request_ready(&port, &startup_diagnostics).await })
            .await;
    });
    // Tray/lifecycle remain available even when record admission needs recovery.
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let presentation = desktop::runtime_presentation(&handle).await;
            let Ok(owner) = native() else {
                break;
            };
            let reply = owner.control(NativeControl::Poll { presentation }).await;
            match reply {
                Ok(NativeReply::Actions { actions }) => {
                    for action in actions {
                        match action {
                            RuntimeAction::Show => desktop::show_window(&handle),
                            RuntimeAction::Toggle => desktop::toggle_connection(handle.clone()),
                            RuntimeAction::Quit => desktop::quit_application(handle.clone()),
                        }
                    }
                }
                _ => {
                    desktop::quit_application(handle.clone());
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    Ok(())
}
