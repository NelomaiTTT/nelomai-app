//! Installed desktop owner. This process owns protected auth, update/selection
//! journals, tray and privileged dispatch; it never constructs product core/UI.
use crate::{
    desktop, platform,
    runtime::{NativeControl, NativeExitReason, NativeReply, RuntimeAction, TraySnapshot},
    PANEL_BASE,
};
use nelomai_client_container::startup_diagnostics as startup;
use nelomai_client_container::{
    host::{CommonHost, HostNativePorts},
    ipc::{BackgroundAction, PrivateBackgroundDispatcher},
    BrokerError, LocalAuthStop, NativeAuthFailure, NativeAuthRequest, RuntimeClientProfile,
    RuntimeForceStop,
};
use nelomai_client_tunnel::TunnelController;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use nelomai_unix_service::{Request, ServiceTransport};
#[cfg(windows)]
use nelomai_windows_service::{Request, ServiceTransport};
use std::{
    collections::VecDeque,
    io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tauri::Manager;

#[cfg(any(target_os = "linux", target_os = "macos"))]
type NativeController = platform::unix::PlatformTunnelController;
#[cfg(windows)]
type NativeController = platform::windows::PlatformTunnelController;
#[cfg(unix)]
type NativeStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type NativeStream = nelomai_client_container::desktop::NativeStream;
type Child = nelomai_client_container::desktop::VerifiedChild;

#[derive(Debug, PartialEq, Eq)]
pub enum InstallationAction {
    Continue,
    LaunchInstalled,
    RepairInstalled,
    InstallCandidate,
}
/// Version ordering is evaluated only after both candidate manifests verify.
/// An old outer shortcut must never overwrite a newer protected installation.
pub fn installation_action(
    candidate: &str,
    installed: Option<&str>,
    protected: bool,
    running_installed: bool,
) -> io::Result<InstallationAction> {
    let candidate = semver::Version::parse(candidate)
        .map_err(|_| io::Error::other("invalid candidate version"))?;
    let installed = installed
        .map(semver::Version::parse)
        .transpose()
        .map_err(|_| io::Error::other("invalid installed version"))?;
    Ok(match installed {
        None => InstallationAction::InstallCandidate,
        Some(installed) if candidate > installed => InstallationAction::InstallCandidate,
        Some(_) if !protected => InstallationAction::RepairInstalled,
        Some(_) if running_installed => InstallationAction::Continue,
        Some(_) => InstallationAction::LaunchInstalled,
    })
}

struct NativeStop {
    child: Mutex<Option<Child>>,
    exit_owner: nelomai_client_container::desktop::RuntimeExitOwner,
    tunnel: Arc<NativeController>,
    operation: tokio::sync::Mutex<NativeOperationState>,
}
#[derive(Default)]
struct NativeOperationState {
    replacement: Option<(nelomai_client_container::UpdateStopProof, bool)>,
    observed_helper_stop: bool,
}
impl NativeOperationState {
    fn check_start(&self, update_pending: bool) -> io::Result<()> {
        if update_pending || self.replacement.is_some() {
            Err(io::Error::other("native start fenced by update"))
        } else {
            Ok(())
        }
    }
    fn begin_start(&mut self, update_pending: bool) -> io::Result<()> {
        self.check_start(update_pending)?;
        self.observed_helper_stop = false;
        Ok(())
    }
    fn restart_proof(&self, host: &CommonHost) -> io::Result<()> {
        if !self.observed_helper_stop {
            return Err(io::Error::other("live helper stop receipt unavailable"));
        }
        let (proof, true) = self
            .replacement
            .as_ref()
            .ok_or_else(|| io::Error::other("installed update receipt unavailable"))?
        else {
            return Err(io::Error::other("installed update receipt unavailable"));
        };
        let current = host
            .update_stop_proof(
                proof.target(),
                nelomai_client_container::UpdateJournalPhase::InstallerOpened,
            )
            .map_err(|_| io::Error::other("installed update receipt changed"))?;
        if &current != proof {
            return Err(io::Error::other("installed update receipt changed"));
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl LocalAuthStop for NativeStop {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        let mut operation = self.operation.lock().await;
        operation.observed_helper_stop = false;
        self.tunnel
            .stop()
            .await
            .map_err(|_| BrokerError::RecoveryRequired)?;
        operation.observed_helper_stop = true;
        Ok(())
    }
}
#[async_trait::async_trait]
impl RuntimeForceStop for NativeStop {
    async fn force_stop(&self, _: &str) -> Result<(), BrokerError> {
        self.exit_owner
            .stop_for_transition(&self.child, async {
                self.stop_local()
                    .await
                    .map_err(|_| io::Error::other("helper stop receipt unavailable"))
            })
            .await
            .map_err(|_| BrokerError::RecoveryRequired)
    }
}
struct DesktopBackground;
#[async_trait::async_trait]
impl PrivateBackgroundDispatcher for DesktopBackground {
    async fn cleanup_push(&self) -> Result<(), BrokerError> {
        Ok(())
    }
    async fn prepare_revocation(&self, _: u64) -> Result<(), BrokerError> {
        Ok(())
    }
    async fn dispatch(
        &self,
        _: NativeAuthRequest,
        _: BackgroundAction,
    ) -> Result<Option<nelomai_client_api::TokenResponse>, NativeAuthFailure> {
        Err(NativeAuthFailure::NotIssued)
    }
}
pub(crate) struct CommonState {
    host: Arc<CommonHost>,
    stop: Arc<NativeStop>,
    presentation: Mutex<TraySnapshot>,
    actions: Mutex<VecDeque<RuntimeAction>>,
    finishing: AtomicBool,
}
impl CommonState {
    async fn finish(self: Arc<Self>, app: tauri::AppHandle, restart: bool) {
        if self.finishing.swap(true, Ordering::AcqRel) {
            return;
        }
        // A full process exit is acknowledged only after actual runtime exit
        // and independent helper stop; a closed window never enters here.
        let operation = self.stop.operation.lock().await;
        let stopped = nelomai_client_container::desktop::stop_runtime_before_helper(
            &self.stop.child,
            async {
                if operation.restart_proof(&self.host).is_ok() {
                    return Ok(());
                }
                self.stop
                    .tunnel
                    .stop()
                    .await
                    .map_err(|_| io::Error::other("helper stop receipt unavailable"))
            },
        )
        .await;
        if stopped.is_err() {
            self.finishing.store(false, Ordering::Release);
            if let Ok(mut presentation) = self.presentation.lock() {
                presentation.disconnect = true;
                presentation.traffic = "Остановка VPN требует повторной попытки".into();
            }
            return;
        }
        if restart {
            #[cfg(target_os = "macos")]
            {
                if crate::macos_launch::restart_after_exit(Path::new(
                    "/Library/Application Support/Nelomai/common/Nelomai.app",
                ))
                .is_ok()
                {
                    app.exit(0);
                } else {
                    self.finishing.store(false, Ordering::Release);
                }
            }
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::process::CommandExt;
                let mut command = {
                    let mut command = std::process::Command::new(
                        "/usr/local/libexec/nelomai/common/AppDir/AppRun",
                    );
                    command
                        .env(
                            "APPIMAGE",
                            "/usr/local/libexec/nelomai/common/Nelomai.AppImage",
                        )
                        .env("APPDIR", "/usr/local/libexec/nelomai/common/AppDir");
                    command
                };
                // exec releases CLOEXEC owner locks before the new image opens
                // auth; a spawned restart could race its still-living owner.
                let _ = command.exec();
                self.finishing.store(false, Ordering::Release);
            }
            #[cfg(windows)]
            app.restart();
        } else {
            app.exit(0);
        }
    }
}
pub(crate) fn queue_action(app: &tauri::AppHandle, action: RuntimeAction) -> bool {
    let Some(state) = app.try_state::<Arc<CommonState>>() else {
        return false;
    };
    let state = state.inner().clone();
    let alive = state
        .stop
        .child
        .lock()
        .ok()
        .and_then(|mut child| child.as_mut().map(|child| !child.exited().unwrap_or(true)))
        .unwrap_or(false);
    if !alive && matches!(action, RuntimeAction::Quit) {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            state.finish(app, false).await;
        });
        return true;
    }
    if let Ok(mut queue) = state.actions.lock() {
        if queue.len() < 16 {
            queue.push_back(action);
        }
    }
    true
}
pub(crate) fn tray_snapshot(app: &tauri::AppHandle) -> Option<TraySnapshot> {
    app.try_state::<Arc<CommonState>>().and_then(|state| {
        state
            .presentation
            .lock()
            .ok()
            .map(|snapshot| snapshot.clone())
    })
}

pub fn run() {
    startup::stage("common.entry");
    if std::env::args().nth(1).as_deref() == Some("--verify-runtime-layout") {
        let result = (|| -> io::Result<()> {
            if !matches!(std::env::args().count(), 3 | 4) {
                return Err(io::Error::other("invalid verification arguments"));
            }
            let path = PathBuf::from(
                std::env::args_os()
                    .nth(2)
                    .ok_or_else(|| io::Error::other("missing runtime layout"))?,
            );
            let runtime = verify_layout(&path)?;
            if runtime.container_version() != env!("CARGO_PKG_VERSION") {
                return Err(io::Error::other("container executable version mismatch"));
            }
            if let Some(previous) = std::env::args_os().nth(3) {
                let previous = verify_layout(Path::new(&previous))?;
                let old = semver::Version::parse(previous.container_version())
                    .map_err(|_| io::Error::other("invalid previous version"))?;
                let new = semver::Version::parse(runtime.container_version())
                    .map_err(|_| io::Error::other("invalid candidate version"))?;
                if new < old {
                    return Err(io::Error::other("container rollback rejected"));
                }
            }
            Ok(())
        })();
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    startup::stage("common.pre_auth_handoff");
    if pre_auth_handoff().unwrap_or_else(|error| {
        startup::error("common.pre_auth_handoff", &error);
        std::process::exit(1)
    }) {
        return;
    }
    let builder = tauri::Builder::default();
    #[cfg(windows)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _, _| {
        queue_action(app, RuntimeAction::Show);
    }));
    let builder = builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            startup::setup(|| {
                use base64::Engine;
                startup::stage("common.resources");
                let resources = installed_resources(app)?;
                let data = app.path().app_data_dir()?;
                // Establish the installed dispatcher identity before protected auth is
                // initialized. This also gives shutdown an actual native stop peer on
                // the first launch, before the user ever connects a tunnel.
                startup::stage("native.prepare");
                tauri::async_runtime::block_on(prepare_native(app.handle().clone()))?;
                startup::stage("common.public_key");
                let key = option_env!("NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64")
                    .map(|value| base64::engine::general_purpose::STANDARD.decode(value))
                    .transpose()?
                    .ok_or_else(|| io::Error::other("pinned runtime manifest key unavailable"))?;
                let native_binding = nelomai_contracts::dispatcher::CommonEngineBinding::default();
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                let tunnel = Arc::new(platform::unix::common_tunnel_controller(
                    native_binding.clone(),
                ));
                #[cfg(windows)]
                let tunnel = Arc::new(platform::windows::common_tunnel_controller(
                    native_binding.clone(),
                ));
                let stop = Arc::new(NativeStop {
                    child: Mutex::new(None),
                    exit_owner: Default::default(),
                    tunnel,
                    operation: tokio::sync::Mutex::new(NativeOperationState::default()),
                });
                #[cfg(target_os = "linux")]
                let fallback = Some(data.join("credentials"));
                #[cfg(not(target_os = "linux"))]
                let fallback = None;
                let updater =
                    platform::updater::DesktopUpdateBackend::from_build(app.handle().clone())
                        .ok()
                        .map(|backend| {
                            Arc::new(backend) as Arc<dyn nelomai_client_updater::UpdateBackend>
                        });
                startup::stage("common.open_host");
                let host = Arc::new(CommonHost::open(
                    &data,
                    &resources.join("runtime"),
                    Some(&key),
                    std::env::consts::OS,
                    std::env::consts::ARCH,
                    || nelomai_client_storage::SystemRecordFactory::new("primary", fallback),
                    nelomai_client_api::ClientApi::new(PANEL_BASE)?,
                    RuntimeClientProfile {
                        platform: crate::commands::current_platform(),
                        platform_version: None,
                        architecture: std::env::consts::ARCH.into(),
                    },
                    HostNativePorts {
                        stop: stop.clone(),
                        force: stop.clone(),
                        background: Arc::new(DesktopBackground),
                        updater,
                        storage: None,
                        relaunch: None,
                    },
                )?);
                startup::stage("native.bind_identity");
                let target = host.native_target();
                let engine =
                    nelomai_contracts::dispatcher::Installation::production(Path::new("/unused"))?
                        .manifest_identity_for(&resources.join("runtime"), target.runtime_slot)?;
                if engine.runtime_version != target.runtime_version
                    || engine.runtime_contract_version != target.runtime_contract_version
                    || engine.container_version != target.container_version
                {
                    return Err(io::Error::other("common native identity mismatch").into());
                }
                native_binding.bind(engine)?;
                startup::stage("runtime.launch");
                let mut child = tauri::async_runtime::block_on(host.launch_desktop(0))?;
                startup::stage("runtime.native_channel");
                let native = child.take_native()?;
                stop.exit_owner.runtime_launched();
                *stop
                    .child
                    .lock()
                    .map_err(|_| io::Error::other("common process state unavailable"))? =
                    Some(child);
                let state = Arc::new(CommonState {
                    host,
                    stop,
                    presentation: Mutex::new(TraySnapshot::default()),
                    actions: Mutex::new(VecDeque::new()),
                    finishing: AtomicBool::new(false),
                });
                app.manage(state.clone());
                startup::stage("common.tray");
                desktop::setup_tray(app)?;
                let handle = app.handle().clone();
                tauri::async_runtime::spawn_blocking(move || serve_native(handle, state, native));
                Ok(())
            })
        });
    let mut context = crate::app_context();
    context.config_mut().app.windows.clear();
    startup::stage("common.build");
    let app = builder
        .build(context)
        .inspect_err(|error| startup::error("common.build", error))
        .expect("common desktop startup failed");
    #[cfg(target_os = "macos")]
    let app = {
        let mut app = app;
        // App::set_activation_policy configures the event loop's initial policy.
        // In setup the loop has already launched, so the common host kept a
        // second Dock tile. Set it before run; only the runtime owns a window.
        app.set_activation_policy(tauri::ActivationPolicy::Accessory);
        app
    };
    startup::stage("common.event_loop");
    app.run(|app, event| {
        #[cfg(target_os = "macos")]
        if let tauri::RunEvent::Reopen { .. } = event {
            queue_action(app, RuntimeAction::Show);
        }
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            if let Some(state) = app.try_state::<Arc<CommonState>>() {
                if !state.finishing.load(Ordering::Acquire) {
                    api.prevent_exit();
                    queue_action(app, RuntimeAction::Quit);
                }
            }
        }
    });
}

fn serve_native(app: tauri::AppHandle, state: Arc<CommonState>, mut stream: NativeStream) {
    use nelomai_client_container::desktop::{read_native_frame, write_native_frame};
    #[cfg(target_os = "macos")]
    let mut storage_opened = false;
    loop {
        let Ok((tag, body)) = read_native_frame(&mut stream) else {
            break;
        };
        let mut exit = None;
        #[cfg(target_os = "macos")]
        let mut storage_endpoint = None;
        let reply = if tag == 1 {
            tauri::async_runtime::block_on(engine_exchange(&state, &body))
        } else if tag == 2 {
            serde_json::from_slice::<NativeControl>(&body)
                .map_err(io::Error::from)
                .and_then(|request| {
                    let reply = match request {
                        #[cfg(target_os = "macos")]
                        NativeControl::OpenStorage => {
                            use nelomai_client_storage::ProtectedRecordFactory;
                            if storage_opened {
                                return Err(io::Error::other("storage already opened"));
                            }
                            let selection = tauri::async_runtime::block_on(state.host.selection())
                                .map_err(|_| io::Error::other("storage selection unavailable"))?;
                            let paths = selection
                                .runtime_paths()
                                .map_err(|_| io::Error::other("storage selection invalid"))?;
                            let records =
                                nelomai_client_storage::SystemRecordFactory::new("primary", None);
                            let records: Vec<_> = paths
                                .iter()
                                .map(|path| records.record(path.namespace()))
                                .collect();
                            let (server, client) = std::os::unix::net::UnixStream::pair()?;
                            std::thread::Builder::new()
                                .name("runtime-storage".into())
                                .spawn(move || crate::macos_storage::serve(server, records))?;
                            storage_endpoint = Some(client);
                            storage_opened = true;
                            NativeReply::Done
                        }
                        NativeControl::Prepare => {
                            let operation =
                                tauri::async_runtime::block_on(state.stop.operation.lock());
                            // Never reinstall/rebind through a replaced common
                            // image. Stop may still contact the existing helper;
                            // all Start/Rebind requests remain fenced separately.
                            if operation.replacement.is_none() {
                                if state
                                    .host
                                    .native_start_blocked()
                                    .map_err(|_| io::Error::other("update state unavailable"))?
                                {
                                    return Err(io::Error::other(
                                        "native preparation fenced by update",
                                    ));
                                }
                                tauri::async_runtime::block_on(prepare_native(app.clone()))?;
                            }
                            NativeReply::Done
                        }
                        NativeControl::Poll { presentation } => {
                            if presentation.traffic.len() > 1024 {
                                return Err(io::Error::other("tray presentation too large"));
                            }
                            *state
                                .presentation
                                .lock()
                                .map_err(|_| io::Error::other("tray unavailable"))? = presentation;
                            let actions = state
                                .actions
                                .lock()
                                .map_err(|_| io::Error::other("tray unavailable"))?
                                .drain(..)
                                .collect();
                            NativeReply::Actions { actions }
                        }
                        NativeControl::Exit { reason } => {
                            match reason {
                                NativeExitReason::Shutdown => {}
                                NativeExitReason::Update => {
                                    if state
                                        .host
                                        .updater_status()
                                        .map_err(|_| io::Error::other("updater unavailable"))?
                                        .phase
                                        != "ready_to_restart"
                                    {
                                        return Err(io::Error::other("update not ready"));
                                    }
                                    tauri::async_runtime::block_on(state.stop.operation.lock())
                                        .restart_proof(&state.host)?;
                                }
                                NativeExitReason::RuntimeSwitch => {
                                    if !state.host.runtime_restart_ready().map_err(|_| {
                                        io::Error::other("runtime switch unavailable")
                                    })? {
                                        return Err(io::Error::other("runtime switch not ready"));
                                    }
                                }
                            }
                            exit = Some(!matches!(reason, NativeExitReason::Shutdown));
                            NativeReply::Done
                        }
                        #[cfg(windows)]
                        NativeControl::DefenderStatus { refresh } => {
                            let status = tauri::async_runtime::block_on(async {
                                if refresh {
                                    platform::windows::refresh_defender_status(&state.stop.tunnel)
                                        .await
                                } else {
                                    platform::windows::defender_status(&state.stop.tunnel).await
                                }
                            })
                            .map_err(|_| io::Error::other("defender status unavailable"))?;
                            NativeReply::Defender { status }
                        }
                        #[cfg(windows)]
                        NativeControl::DefenderRepair => {
                            let status = tauri::async_runtime::block_on(
                                platform::windows::repair_defender_exclusion(&state.stop.tunnel),
                            )
                            .map_err(|_| io::Error::other("defender repair failed"))?;
                            NativeReply::Defender { status }
                        }
                    };
                    serde_json::to_vec(&reply).map_err(Into::into)
                })
        } else {
            Err(io::Error::other("native command rejected"))
        };
        let (response_tag, response) = match reply {
            Ok(body) => (tag, body),
            Err(_) => (255, b"common operation failed".to_vec()),
        };
        if write_native_frame(&mut stream, response_tag, &response).is_err() {
            break;
        }
        #[cfg(target_os = "macos")]
        if let Some(endpoint) = storage_endpoint {
            if crate::macos_storage::send_endpoint(&mut stream, &endpoint).is_err() {
                break;
            }
        }
        if let Some(restart) = exit {
            tauri::async_runtime::block_on(state.finish(app, restart));
            return;
        }
    }
    // Intentional termination leaves the active transition in control through
    // helper acknowledgement and durable journal completion. Unsolicited EOF
    // still needs ordered finish; neither kind of EOF is a helper stop receipt.
    if state.stop.exit_owner.finish_on_native_eof() {
        tauri::async_runtime::block_on(state.finish(app, false));
    }
}
async fn engine_exchange(state: &CommonState, body: &[u8]) -> io::Result<Vec<u8>> {
    let request: Request = serde_json::from_slice(body)?;
    if matches!(request, Request::Start { .. }) {
        state
            .host
            .before_native_tunnel_start()
            .await
            .map_err(|_| io::Error::other("common start rejected"))?;
    }
    let mut operation = state.stop.operation.lock().await;
    if matches!(request, Request::Start { .. } | Request::RebindUdp { .. }) {
        operation.begin_start(
            state
                .host
                .native_start_blocked()
                .map_err(|_| io::Error::other("update state unavailable"))?
                || !runtime_is_alive(state),
        )?;
    }
    let response = state
        .stop
        .tunnel
        .transport()
        .exchange(request)
        .await
        .map_err(|_| io::Error::other("engine unavailable"))?;
    serde_json::to_vec(&response).map_err(Into::into)
}
fn runtime_is_alive(state: &CommonState) -> bool {
    state
        .stop
        .child
        .lock()
        .ok()
        .and_then(|mut child| child.as_mut().map(|child| !child.exited().unwrap_or(true)))
        .unwrap_or(false)
}
pub(crate) async fn begin_installation<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    target: &str,
) -> io::Result<nelomai_client_container::UpdateStopProof> {
    let state = app
        .try_state::<Arc<CommonState>>()
        .ok_or_else(|| io::Error::other("common owner unavailable"))?
        .inner()
        .clone();
    let mut operation = state.stop.operation.lock().await;
    if !operation.observed_helper_stop {
        return Err(io::Error::other("live helper stop receipt unavailable"));
    }
    let proof = state
        .host
        .update_stop_proof(
            target,
            nelomai_client_container::UpdateJournalPhase::LocalStopped,
        )
        .map_err(|_| io::Error::other("update stop proof unavailable"))?;
    if operation
        .replacement
        .as_ref()
        .is_some_and(|(previous, _)| previous != &proof)
    {
        return Err(io::Error::other("update operation changed"));
    }
    operation.replacement = Some((proof.clone(), false));
    Ok(proof)
}
#[cfg(not(windows))]
pub(crate) async fn installation_succeeded<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    proof: nelomai_client_container::UpdateStopProof,
) -> io::Result<()> {
    let state = app
        .try_state::<Arc<CommonState>>()
        .ok_or_else(|| io::Error::other("common owner unavailable"))?
        .inner()
        .clone();
    let mut operation = state.stop.operation.lock().await;
    let current = state
        .host
        .update_stop_proof(
            proof.target(),
            nelomai_client_container::UpdateJournalPhase::LocalStopped,
        )
        .map_err(|_| io::Error::other("update operation changed"))?;
    if current != proof
        || operation
            .replacement
            .as_ref()
            .is_none_or(|(expected, _)| expected != &proof)
    {
        return Err(io::Error::other("update operation changed"));
    }
    operation.replacement = Some((proof, true));
    Ok(())
}
#[cfg(windows)]
pub(crate) async fn handoff_windows_installer<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    proof: nelomai_client_container::UpdateStopProof,
    launch: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let state = app
        .try_state::<Arc<CommonState>>()
        .ok_or_else(|| io::Error::other("common owner unavailable"))?
        .inner()
        .clone();
    // Keep the same native operation guard until the non-returning installer
    // takes over. Queued Start/Rebind cannot invalidate this stop acknowledgement.
    let operation = state.stop.operation.lock().await;
    state
        .stop
        .exit_owner
        .handoff_installer(
            &state.stop.child,
            async {
                if !operation.observed_helper_stop
                    || operation.replacement.as_ref() != Some(&(proof.clone(), false))
                    || state
                        .host
                        .update_stop_proof(
                            proof.target(),
                            nelomai_client_container::UpdateJournalPhase::LocalStopped,
                        )
                        .map_err(|_| io::Error::other("pending update authority unavailable"))?
                        != proof
                {
                    return Err(io::Error::other("pending update authority changed"));
                }
                // LocalStopped is already fsync'd by the existing barrier and linked to
                // the exact operation/source/target/helper receipt. It remains pending:
                // ShellExecute (whose result stock updater ignores) is not installation.
                Ok(())
            },
            launch,
        )
        .await
}
async fn prepare_native(app: tauri::AppHandle) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let result = platform::unix::prepare_tunnel(app).await;
    #[cfg(windows)]
    let result = {
        let _ = app;
        platform::windows::prepare_tunnel().await
    };
    result
        .inspect_err(|error| startup::error("native.prepare", error))
        .map_err(|_| io::Error::other("common preparation failed"))
}
fn installed_resources(app: &tauri::App) -> io::Result<PathBuf> {
    app.path()
        .resource_dir()
        .map_err(|_| io::Error::other("common resources unavailable"))
}
fn verify_layout(path: &Path) -> io::Result<nelomai_client_container::desktop::VerifiedRuntime> {
    use base64::Engine;
    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path)?.uid()
    };
    #[cfg(windows)]
    let owner = 0;
    let key = option_env!("NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64")
        .and_then(|value| base64::engine::general_purpose::STANDARD.decode(value).ok())
        .ok_or_else(|| io::Error::other("pinned runtime manifest key unavailable"))?;
    nelomai_client_container::desktop::VerifiedRuntime::open(
        path,
        &key,
        nelomai_contracts::RuntimeSlot::Latest,
        std::env::consts::OS,
        std::env::consts::ARCH,
        owner,
    )
}
#[cfg(unix)]
fn protected_executable(path: &Path) -> bool {
    path.ancestors()
        .all(|path| nelomai_contracts::dispatcher::trusted(path, 0).is_ok())
}
fn pre_auth_handoff() -> io::Result<bool> {
    let original = std::env::current_exe()?;
    #[cfg(windows)]
    nelomai_client_container::desktop::verify_protected_path(&original)?;
    #[cfg(unix)]
    let executable = std::fs::canonicalize(original)?;
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            return Err(io::Error::other("product cannot run as root"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let source = executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or_else(|| io::Error::other("common app bundle unavailable"))?;
        let installed = Path::new("/Library/Application Support/Nelomai/common/Nelomai.app");
        let installed_exe = installed.join("Contents/MacOS/nelomai-app");
        let candidate = verify_layout(&source.join("Contents/Resources/runtime"))?;
        let existing = if installed.exists() {
            Some(verify_layout(
                &installed.join("Contents/Resources/runtime"),
            )?)
        } else {
            None
        };
        let protected = protected_executable(&installed_exe)
            && existing
                .as_ref()
                .is_some_and(|runtime| protected_executable(runtime.executable()));
        let action = installation_action(
            candidate.container_version(),
            existing.as_ref().map(|runtime| runtime.container_version()),
            protected,
            executable == installed_exe,
        )?;
        if action == InstallationAction::Continue {
            return Ok(false);
        }
        if action != InstallationAction::LaunchInstalled {
            let selected = if action == InstallationAction::RepairInstalled {
                installed
            } else {
                source
            };
            let resources = selected.join("Contents/Resources");
            let status = platform::unix::installer_status(
                std::process::Command::new("/usr/bin/osascript")
                    .arg(resources.join("install-common-macos.applescript"))
                    .arg(resources.join("install-common-macos.sh"))
                    .arg(selected),
            )
            .map_err(|_| io::Error::other("common installation failed"))?;
            if !status.success() {
                return Err(io::Error::other("common installation cancelled"));
            }
        }
        if !protected_executable(&installed_exe) {
            return Err(io::Error::other("installed common broker required"));
        }
        verify_layout(&installed.join("Contents/Resources/runtime"))?;
        crate::macos_launch::launch_application(installed)?;
        Ok(true)
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let installed = Path::new("/usr/local/libexec/nelomai/common");
        let installed_exe = installed.join("AppDir/usr/bin/nelomai-app");
        let installed_resources = installed.join("AppDir/usr/lib/Nelomai");
        let source_dir = executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or_else(|| io::Error::other("AppImage layout unavailable"))?;
        let source_resources = source_dir.join("usr/lib/Nelomai");
        let candidate = verify_layout(&source_resources.join("runtime"))?;
        let existing = if installed_resources.join("runtime").exists() {
            Some(verify_layout(&installed_resources.join("runtime"))?)
        } else {
            None
        };
        let protected = protected_executable(&installed_exe)
            && existing
                .as_ref()
                .is_some_and(|runtime| protected_executable(runtime.executable()));
        let action = installation_action(
            candidate.container_version(),
            existing.as_ref().map(|runtime| runtime.container_version()),
            protected,
            executable == installed_exe,
        )?;
        if action == InstallationAction::Continue {
            return Ok(false);
        }
        if action != InstallationAction::LaunchInstalled {
            let archive = if action == InstallationAction::RepairInstalled {
                installed.join("Nelomai.AppImage")
            } else {
                PathBuf::from(
                    std::env::var_os("APPIMAGE")
                        .ok_or_else(|| io::Error::other("whole AppImage required"))?,
                )
            };
            let installer = if installed.join("install-common-linux.sh").exists() {
                installed.join("install-common-linux.sh")
            } else {
                source_resources.join("install-common-linux.sh")
            };
            let sha = nelomai_contracts::dispatcher::file_digest(&archive)?;
            let status = platform::unix::installer_status(
                std::process::Command::new("/usr/bin/pkexec")
                    .arg("/bin/sh")
                    .arg(installer)
                    .arg(archive)
                    .arg(sha),
            )
            .map_err(|_| io::Error::other("common installation failed"))?;
            if !status.success() {
                return Err(io::Error::other("common installation cancelled"));
            }
        }
        if !protected_executable(&installed_exe) {
            return Err(io::Error::other("installed common broker required"));
        }
        verify_layout(&installed_resources.join("runtime"))?;
        Err(std::process::Command::new(installed.join("AppDir/AppRun"))
            .env("APPIMAGE", installed.join("Nelomai.AppImage"))
            .env("APPDIR", installed.join("AppDir"))
            .exec())
    }
    #[cfg(windows)]
    Ok(false)
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    #[tokio::test]
    async fn queued_native_start_is_checked_after_the_inflight_operation_releases() {
        let operation = Arc::new(tokio::sync::Mutex::new(NativeOperationState::default()));
        let pending = Arc::new(AtomicBool::new(false));
        let inflight = operation.lock().await;
        assert!(inflight.check_start(false).is_ok());
        let queued = {
            let operation = operation.clone();
            let pending = pending.clone();
            tokio::spawn(async move {
                operation
                    .lock()
                    .await
                    .begin_start(pending.load(Ordering::Acquire))
            })
        };
        tokio::task::yield_now().await;
        pending.store(true, Ordering::Release);
        drop(inflight);
        assert!(
            queued.await.unwrap().is_err(),
            "a queued native Start must not use a pre-barrier decision"
        );
        assert!(operation.lock().await.check_start(true).is_err());
        let mut guard = operation.lock().await;
        guard.observed_helper_stop = true;
        assert!(guard.begin_start(true).is_err());
        assert!(
            guard.observed_helper_stop,
            "denied Start preserves quiescence"
        );
        guard.begin_start(false).unwrap();
        assert!(
            !guard.observed_helper_stop,
            "any admitted Start invalidates previous stop proof before native effects"
        );
    }
}
