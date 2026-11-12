//! Installed desktop owner. This process owns protected auth, update/selection
//! journals, tray and privileged dispatch; it never constructs product core/UI.
use crate::{
    desktop, platform,
    runtime::{NativeControl, NativeExitReason, NativeReply, RuntimeAction, TraySnapshot},
    PANEL_BASE,
};
use nelomai_client_container::startup_diagnostics as startup;
use nelomai_client_container::{
    host::{prepare_host, CommonHost, HostError, HostNativePorts},
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
        Arc, Mutex, OnceLock,
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
    #[cfg(target_os = "macos")]
    RepairDownloadMetadata,
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

#[cfg(target_os = "macos")]
fn macos_installation_action(
    candidate: &nelomai_contracts::VerifiedContainerManifest,
    installed: Option<&nelomai_contracts::VerifiedContainerManifest>,
    protected: bool,
    executable: &Path,
    installed_bundle: &Path,
) -> io::Result<InstallationAction> {
    let running_installed = executable == installed_bundle.join("Contents/MacOS/nelomai-app");
    let candidate = candidate.manifest();
    let installed = installed.map(|manifest| manifest.manifest());
    let action = installation_action(
        &candidate.container_version,
        installed.map(|manifest| manifest.container_version.as_str()),
        protected,
        running_installed,
    )?;
    // Different signed candidates can share a version during acceptance. Use
    // their authenticated contents, including stable, to distinguish them.
    // An identical copy remains an idempotent launch; lower versions still
    // cannot replace a newer installation, and an admitted owner continues.
    if matches!(
        action,
        InstallationAction::LaunchInstalled | InstallationAction::RepairInstalled
    ) && installed.is_some_and(|installed| {
        candidate.container_version == installed.container_version && candidate != installed
    }) {
        return Ok(InstallationAction::InstallCandidate);
    }
    // Repair a quarantined handoff target, never an already admitted owner:
    // reopening that same live process before returning would lose the launch.
    if action == InstallationAction::LaunchInstalled
        && crate::macos_installation::requires_installation_repair(installed_bundle)?
    {
        Ok(InstallationAction::RepairDownloadMetadata)
    } else {
        Ok(action)
    }
}

#[cfg(target_os = "macos")]
fn macos_installer_command(
    action: InstallationAction,
    source: &Path,
    installed: &Path,
    uid: u32,
) -> std::process::Command {
    let selected = if matches!(
        action,
        InstallationAction::RepairInstalled | InstallationAction::RepairDownloadMetadata
    ) {
        installed
    } else {
        source
    };
    // The executing candidate defines the protocol, even when repairing a newer
    // protected version. Metadata repair never replaces that version's bytes.
    let resources = source.join("Contents/Resources");
    let mut command = std::process::Command::new("/usr/bin/osascript");
    command
        .arg(resources.join("install-common-macos.applescript"))
        .arg(resources.join("install-common-macos.sh"))
        .arg(uid.to_string())
        .arg(selected);
    if action == InstallationAction::RepairDownloadMetadata {
        command.arg("--repair-download-metadata");
    }
    command
}

#[cfg(target_os = "macos")]
fn run_macos_pre_auth_installer(command: &mut std::process::Command) -> io::Result<bool> {
    use std::io::{Read, Seek, SeekFrom};

    let mut stderr = tempfile::tempfile()?;
    command.stderr(stderr.try_clone()?);
    let status = platform::unix::installer_status(command)
        .map_err(|_| io::Error::other("common installation failed"))?;
    if status.success() {
        return Ok(true);
    }
    if status.code() == Some(1) {
        // osascript uses exit 1 for both cancellation and script failures.
        // Its final numeric error is stable across locales. Keep stderr private.
        const TAIL_BYTES: u64 = 128;
        let size = stderr.metadata()?.len();
        stderr.seek(SeekFrom::Start(size.saturating_sub(TAIL_BYTES)))?;
        let mut tail = Vec::new();
        stderr.take(TAIL_BYTES).read_to_end(&mut tail)?;
        if tail.trim_ascii_end().ends_with(b" (-128)") {
            return Ok(false);
        }
    }
    Err(io::Error::other("common installation failed"))
}

#[cfg(all(test, target_os = "macos"))]
#[path = "macos_installation_tests.rs"]
mod macos_installation_tests;

#[cfg(any(target_os = "linux", all(test, unix)))]
#[path = "linux_installation.rs"]
mod linux_installation;

struct NativeStop {
    child: Mutex<Option<Child>>,
    exit_owner: nelomai_client_container::desktop::RuntimeExitOwner,
    tunnel: Arc<NativeController>,
    operation: Arc<tokio::sync::Mutex<NativeOperationState>>,
}
impl NativeStop {
    async fn runtime_operation(
        &self,
    ) -> io::Result<tokio::sync::MutexGuard<'_, NativeOperationState>> {
        // macOS authorization may keep the installer here for 120s. Native IPC
        // has a shorter deadline: reject contention without closing its stream
        // or allowing any command to bypass the held installation/stop gate.
        #[cfg(target_os = "macos")]
        return self
            .operation
            .try_lock()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "native operation busy"));
        #[cfg(not(target_os = "macos"))]
        Ok(self.operation.lock().await)
    }
}
#[derive(Default)]
struct NativeOperationState {
    replacement: Option<(nelomai_client_container::UpdateStopProof, bool)>,
    observed_helper_stop: bool,
    #[cfg(target_os = "macos")]
    broker_replaced: bool,
    #[cfg(target_os = "macos")]
    exit_requested: bool,
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
    #[cfg(target_os = "macos")]
    fn check_request(&self) -> io::Result<()> {
        if self.broker_replaced || self.exit_requested {
            return Err(io::Error::other("native broker was replaced by update"));
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    async fn exchange_request(
        &self,
        transport: &impl ServiceTransport,
        request: Request,
    ) -> io::Result<Vec<u8>> {
        self.check_request()?;
        let response = transport
            .exchange(request)
            .await
            .map_err(|_| io::Error::other("engine unavailable"))?;
        serde_json::to_vec(&response).map_err(Into::into)
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
        let current = host.update_stop_proof(
            proof.target(),
            nelomai_client_container::UpdateJournalPhase::InstallerOpened,
        );
        // A successful native replacement can finish before the async updater
        // writes InstallerOpened. The same exact durable stop proof still applies.
        #[cfg(target_os = "macos")]
        let current = current.or_else(|_| {
            host.update_stop_proof(
                proof.target(),
                nelomai_client_container::UpdateJournalPhase::LocalStopped,
            )
        });
        let current = current.map_err(|_| io::Error::other("installed update receipt changed"))?;
        if &current != proof {
            return Err(io::Error::other("installed update receipt changed"));
        }
        Ok(())
    }
}
#[cfg(target_os = "macos")]
impl NativeStop {
    async fn stop_after_installation(&self) -> io::Result<()> {
        // The caller holds the native gate and verified the installed stop proof.
        // Reuse normal common teardown, including when unsolicited EOF already
        // requested finish; that earlier EOF is not a competing update operation.
        nelomai_client_container::desktop::stop_runtime_before_helper(&self.child, async { Ok(()) })
            .await
    }
}
fn verified_native_engine(
    installation: &nelomai_contracts::dispatcher::Installation,
    resources: &Path,
    target: &nelomai_client_api::RuntimeTarget,
) -> io::Result<nelomai_contracts::dispatcher::EngineIdentity> {
    let engine = installation.manifest_identity_for(resources, target.runtime_slot)?;
    if engine.runtime_version != target.runtime_version
        || engine.runtime_contract_version != target.runtime_contract_version
        || engine.container_version != target.container_version
    {
        return Err(io::Error::other("common native identity mismatch"));
    }
    Ok(engine)
}

#[cfg(any(windows, target_os = "linux", test))]
fn retire_startup_engine(
    source: &nelomai_contracts::dispatcher::EngineIdentity,
    target: &nelomai_contracts::dispatcher::EngineIdentity,
    mut exchange: impl FnMut(
        &nelomai_contracts::dispatcher::DispatcherRequest,
    ) -> io::Result<nelomai_contracts::dispatcher::DispatcherResponse>,
) -> io::Result<()> {
    const MAX_RETRIES: usize = 2;
    // A timed-out Stop can still be running. Each retry rechecks the
    // dispatcher identity before sending another Stop for the source.
    for _ in 0..MAX_RETRIES {
        match retire_startup_engine_once(source, target, &mut exchange) {
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            result => return result,
        }
    }
    retire_startup_engine_once(source, target, exchange)
}

#[cfg(any(windows, target_os = "linux", test))]
fn retire_startup_engine_once(
    source: &nelomai_contracts::dispatcher::EngineIdentity,
    target: &nelomai_contracts::dispatcher::EngineIdentity,
    mut exchange: impl FnMut(
        &nelomai_contracts::dispatcher::DispatcherRequest,
    ) -> io::Result<nelomai_contracts::dispatcher::DispatcherResponse>,
) -> io::Result<()> {
    use nelomai_contracts::dispatcher::DispatcherRequest;
    if source.manifest_sha256 != target.manifest_sha256 {
        return Err(io::Error::other("native switch manifest changed"));
    }
    let observed = exchange(&DispatcherRequest::Version {
        contract_version: 1,
    })?;
    if !observed.ok || observed.contract_version != 1 {
        return Err(io::Error::other("native switch identity unavailable"));
    }
    if observed.identity.as_ref() == Some(target) {
        return Ok(());
    }
    if observed.identity.as_ref() != Some(source) {
        return Err(io::Error::other("native switch identity mismatch"));
    }

    // Even a non-running source can have pending dispatcher cleanup.
    let stopped = exchange(&DispatcherRequest::Stop {
        contract_version: 1,
        identity: source.clone(),
    })?;
    if stopped.ok
        && !stopped.running
        && stopped.contract_version == 1
        && stopped.identity.as_ref() == Some(source)
    {
        Ok(())
    } else {
        Err(io::Error::other("native switch stop receipt unavailable"))
    }
}

// Only the installed Common owner calls this under its native operation gate.
async fn stop_helper_for_exit(
    tunnel: &NativeController,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    #[cfg(any(windows, target_os = "linux"))]
    {
        // Dispatcher Stop cleans the owned pair and waits for the engine to
        // exit. A scoped Stop alone leaves a reusable engine in the old slot.
        tunnel.retire_engine().await
    }
    #[cfg(target_os = "macos")]
    {
        tunnel.stop().await?;
        tunnel.retire_engine().await?;
        Ok(())
    }
}

impl NativeStop {
    async fn stop_native(&self, for_transition: bool) -> Result<(), BrokerError> {
        let mut operation = self.operation.clone().lock_owned().await;
        let tunnel = self.tunnel.clone();
        tokio::spawn(async move {
            #[cfg(target_os = "macos")]
            if operation.check_request().is_err() {
                return Err(BrokerError::RecoveryRequired);
            }
            operation.observed_helper_stop = false;
            let result = if for_transition || cfg!(target_os = "macos") {
                stop_helper_for_exit(&tunnel).await
            } else {
                tunnel.stop().await
            };
            result.map_err(|_| BrokerError::RecoveryRequired)?;
            operation.observed_helper_stop = true;
            Ok(())
        })
        .await
        .map_err(|_| BrokerError::RecoveryRequired)?
    }
}

#[async_trait::async_trait]
impl LocalAuthStop for NativeStop {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        self.stop_native(false).await
    }

    async fn stop_local_for_transition(&self) -> Result<(), BrokerError> {
        self.stop_native(true).await
    }
}
#[async_trait::async_trait]
impl RuntimeForceStop for NativeStop {
    async fn force_stop(&self, _: &str) -> Result<(), BrokerError> {
        self.exit_owner
            .stop_for_transition(&self.child, async {
                self.stop_local_for_transition()
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
    // Set after unexpected EOF cleanup is attempted. The native pump has gone,
    // and a successful stop receipt remains valid through the window's Close.
    runtime_failure_cleanup: OnceLock<bool>,
}
#[derive(Clone, Copy)]
enum CommonFinish {
    Quit,
    Restart,
    RuntimeFailure,
}
impl CommonState {
    async fn finish(self: Arc<Self>, app: tauri::AppHandle, reason: CommonFinish) {
        if self.finishing.swap(true, Ordering::AcqRel) {
            return;
        }
        // A full process exit is acknowledged only after actual runtime exit
        // and independent helper stop; a closed window never enters here.
        let operation = self.stop.operation.lock().await;
        #[cfg(target_os = "macos")]
        if operation.exit_requested {
            return;
        }
        let mut stopped_for_replacement = false;
        let stopped = self.runtime_failure_cleanup.get() == Some(&true)
            || nelomai_client_container::desktop::stop_runtime_before_helper(
                &self.stop.child,
                async {
                    if operation.restart_proof(&self.host).is_ok() {
                        stopped_for_replacement = true;
                        return Ok(());
                    }
                    #[cfg(target_os = "macos")]
                    operation.check_request()?;
                    stop_helper_for_exit(&self.stop.tunnel)
                        .await
                        .map_err(|_| io::Error::other("helper stop receipt unavailable"))
                },
            )
            .await
            .is_ok();
        if !stopped {
            if let Ok(mut presentation) = self.presentation.lock() {
                presentation.disconnect = true;
                presentation.traffic = "Остановка VPN требует повторной попытки".into();
            }
        }
        if matches!(reason, CommonFinish::RuntimeFailure) && !stopped_for_replacement {
            let _ = self.runtime_failure_cleanup.set(stopped);
            self.finishing.store(false, Ordering::Release);
            drop(operation);
            present_runtime_failure(&app);
            return;
        }
        if !stopped {
            self.finishing.store(false, Ordering::Release);
            return;
        }
        if matches!(reason, CommonFinish::Restart) {
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
    if matches!(action, RuntimeAction::Show) {
        if let Some(window) = app.get_webview_window("startup-failure") {
            let _ = window.unminimize();
            let _ = window.set_focus();
            return true;
        }
    }
    let Some(state) = app.try_state::<Arc<CommonState>>() else {
        return false;
    };
    let state = state.inner().clone();
    let alive = || {
        state
            .stop
            .child
            .lock()
            .ok()
            .and_then(|mut child| child.as_mut().map(|child| !child.exited().unwrap_or(true)))
            .unwrap_or(false)
    };
    // The failure window may belong to Common while its child is still alive
    // and unable to poll. Its Quit must go straight to guarded shutdown.
    if matches!(action, RuntimeAction::Quit)
        && (app
            .try_state::<crate::support_diagnostics::CommonFailureStage>()
            .is_some()
            || state.runtime_failure_cleanup.get().is_some()
            || !alive())
    {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            state.finish(app, CommonFinish::Quit).await;
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

pub(crate) fn diagnostic_runtime_identity(
    app: &tauri::AppHandle,
) -> Option<nelomai_contracts::RuntimeIdentity> {
    let state = app.try_state::<Arc<CommonState>>()?;
    let child = state.stop.child.try_lock().ok()?;
    child.as_ref()?;
    // launch_desktop verifies the child's target against this frozen identity.
    state.host.native_target().identity(None).ok()
}

pub(crate) fn update_presentation(app: &tauri::AppHandle) -> bool {
    let Some(state) = app.try_state::<Arc<CommonState>>() else {
        return false;
    };
    if let Some(offer) = state.host.take_update_notification() {
        desktop::notify_update(app, offer.version);
    }
    state
        .host
        .updater_status_v2()
        .map(|s| s.update_available)
        .unwrap_or(false)
}
pub fn run() {
    const PRE_AUTH_STAGE: &str = "common.pre_auth_handoff";
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
    startup::stage(PRE_AUTH_STAGE);
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        startup::error(
            PRE_AUTH_STAGE,
            &io::Error::other("product cannot run as root"),
        );
        std::process::exit(1);
    }
    let pre_auth_reason = match pre_auth_handoff() {
        Ok(PreAuthHandoff::Continue) => None,
        #[cfg(target_os = "macos")]
        Ok(PreAuthHandoff::Complete) => return,
        #[cfg(unix)]
        Ok(PreAuthHandoff::Declined(error)) => {
            startup::error(PRE_AUTH_STAGE, &error);
            std::process::exit(1);
        }
        Err(failure) => {
            let reason = failure.code();
            startup::error(PRE_AUTH_STAGE, &io::Error::other(reason));
            Some(reason)
        }
    };
    let diagnostics_only = pre_auth_reason.is_some();
    let builder = tauri::Builder::default();
    let builder = if diagnostics_only {
        builder
    } else {
        #[cfg(windows)]
        let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _, _| {
            queue_action(app, RuntimeAction::Show);
        }));
        builder
            .plugin(tauri_plugin_updater::Builder::new().build())
            .plugin(tauri_plugin_notification::init())
    };
    let builder = builder
        .plugin(tauri_plugin_dialog::init())
        .manage(crate::support_diagnostics::SupportReportState::default())
        .invoke_handler(tauri::generate_handler![
            crate::support_diagnostics::app_collect_support_diagnostics,
            crate::support_diagnostics::app_save_support_diagnostics,
            crate::support_diagnostics::app_send_support_diagnostics,
        ])
        .setup(move |app| {
            let mut stage = PRE_AUTH_STAGE;
            let result = startup::setup(|| {
                if diagnostics_only {
                    return Ok(());
                }
                use base64::Engine;
                stage = "common.resources";
                startup::stage(stage);
                let resources = installed_resources(app)?;
                let data = app.path().app_data_dir()?;
                // Establish the installed dispatcher identity before protected auth is
                // initialized. This also gives shutdown an actual native stop peer on
                // the first launch, before the user ever connects a tunnel.
                stage = "native.prepare";
                startup::stage(stage);
                tauri::async_runtime::block_on(prepare_native(app.handle().clone(), true))?;
                stage = "common.public_key";
                startup::stage(stage);
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
                    operation: Arc::new(tokio::sync::Mutex::new(NativeOperationState::default())),
                });
                #[cfg(target_os = "linux")]
                let fallback = Some(data.join("credentials"));
                #[cfg(not(target_os = "linux"))]
                let fallback = None;
                let api = nelomai_client_api::ClientApi::new(PANEL_BASE)?;
                stage = "common.open_host";
                startup::stage(stage);
                let prepared = prepare_host(
                    &data,
                    &resources.join("runtime"),
                    Some(&key),
                    std::env::consts::OS,
                    std::env::consts::ARCH,
                    || nelomai_client_storage::SystemRecordFactory::new("primary", fallback),
                )
                .map_err(HostError::from)?;
                app.manage(crate::support_diagnostics::SupportDataRoot(
                    prepared.owner.root().to_owned(),
                ));
                // Updater cache recovery assumes this process is the only owner.
                let updater = platform::updater::DesktopUpdateBackend::from_build(
                    app.handle().clone(),
                    api.clone(),
                )
                .ok()
                .map(|backend| Arc::new(backend) as Arc<dyn nelomai_client_updater::UpdateBackend>);
                let host = Arc::new(CommonHost::from_prepared(
                    prepared,
                    api,
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
                stage = "native.bind_identity";
                startup::stage(stage);
                let target = host.native_target();
                let runtime_resources = resources.join("runtime");
                let installation =
                    nelomai_contracts::dispatcher::Installation::production(Path::new("/unused"))?;
                let engine = verified_native_engine(&installation, &runtime_resources, target)?;
                #[cfg(any(windows, target_os = "linux"))]
                if let Some(source) = host.coordinator().startup_engine_source(target)? {
                    let source =
                        verified_native_engine(&installation, &runtime_resources, &source)?;
                    #[cfg(windows)]
                    let exchange = nelomai_windows_service::windows::dispatcher_exchange;
                    #[cfg(target_os = "linux")]
                    let exchange = nelomai_unix_service::dispatcher_exchange;
                    retire_startup_engine(&source, &engine, |request| {
                        exchange(request).map_err(|error| {
                            #[cfg(target_os = "linux")]
                            match error {
                                nelomai_unix_service::ServiceError::DispatcherTimeout => {
                                    return io::Error::new(io::ErrorKind::TimedOut, error);
                                }
                                nelomai_unix_service::ServiceError::DispatcherBusy => {
                                    return io::Error::new(io::ErrorKind::WouldBlock, error);
                                }
                                _ => {}
                            }
                            io::Error::other(error)
                        })
                    })?;
                }
                native_binding.bind(engine)?;
                stage = "runtime.launch";
                startup::stage(stage);
                let mut child = tauri::async_runtime::block_on(host.launch_desktop(0))?;
                stage = "runtime.native_channel";
                startup::stage(stage);
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
                    runtime_failure_cleanup: OnceLock::new(),
                });
                app.manage(state.clone());
                let scheduler = state.host.clone();
                tauri::async_runtime::spawn(async move {
                    scheduler.start_update_scheduler();
                });
                let handle = app.handle().clone();
                tauri::async_runtime::spawn_blocking(move || serve_native(handle, state, native));
                // Let the child finish native bootstrap while the tray starts.
                stage = "common.tray";
                startup::stage(stage);
                desktop::setup_tray(app)?;
                Ok(())
            });
            if diagnostics_only || result.is_err() {
                // Tauri panics on setup Err inside macOS didFinishLaunching;
                // unwinding across that Objective-C callback aborts the process.
                // Keep protected records intact and show a separate, inert UI.
                if let Err(error) = show_startup_failure(app.handle(), stage, pre_auth_reason) {
                    startup::error("common.failure_window", &error);
                    std::process::exit(1);
                }
            }
            Ok(())
        });
    let mut context = crate::app_context();
    context.config_mut().app.windows.clear();
    startup::stage("common.build");
    let app = builder.build(context).unwrap_or_else(|error| {
        startup::error("common.build", &error);
        std::process::exit(1);
    });
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

fn show_startup_failure(
    app: &tauri::AppHandle,
    stage: &'static str,
    reason: Option<&'static str>,
) -> tauri::Result<()> {
    if !app.manage(crate::support_diagnostics::CommonFailureStage(
        stage, reason,
    )) {
        return Ok(());
    }
    let handle = app.clone();
    let (asset, title) = if stage == "runtime.native_exit" {
        (
            "startup-failure.html#interrupted",
            "Работа Nelomai прервана",
        )
    } else {
        ("startup-failure.html", "Nelomai — ошибка запуска")
    };
    let window = tauri::WebviewWindowBuilder::new(
        app,
        "startup-failure",
        tauri::WebviewUrl::App(asset.into()),
    )
    .title(title)
    .inner_size(560.0, 320.0)
    .resizable(false)
    .build()?;
    window.on_window_event(move |event| {
        if let tauri::WindowEvent::CloseRequested { api, .. } = event {
            // Keep the retry window while guarded child/helper cleanup is
            // pending or failed; only its successful app.exit may close it.
            api.prevent_close();
            if !queue_action(&handle, RuntimeAction::Quit) {
                handle.exit(0);
            }
        }
    });
    Ok(())
}

fn present_runtime_failure(app: &tauri::AppHandle) {
    startup::error(
        "runtime.native_exit",
        &io::Error::other("runtime native channel closed unexpectedly"),
    );
    // Tauri dispatches the build to its UI thread from this blocking worker.
    // Creating WebView2 in an event handler can deadlock on Windows.
    if let Err(error) = show_startup_failure(app, "runtime.native_exit", None) {
        startup::error("common.failure_window", &error);
        queue_action(app, RuntimeAction::Quit);
    }
}

pub(crate) fn show_support_diagnostics(app: tauri::AppHandle) {
    const LABEL: &str = "support-diagnostics";
    static OPENING: Mutex<()> = Mutex::new(());

    // The tray callback must return before creating a WebView2 window.
    tauri::async_runtime::spawn_blocking(move || {
        let Ok(_opening) = OPENING.try_lock() else {
            return;
        };
        let window = match app.get_webview_window(LABEL) {
            Some(window) => window,
            None => {
                let built = tauri::WebviewWindowBuilder::new(
                    &app,
                    LABEL,
                    tauri::WebviewUrl::App("startup-failure.html#support".into()),
                )
                .title("Nelomai — диагностика")
                .inner_size(560.0, 380.0)
                .visible(false)
                .build();
                let window = match built {
                    Ok(window) => window,
                    Err(error) => {
                        startup::error("common.support_window", &error);
                        return;
                    }
                };
                let handle = window.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        // Closing Common's last window would ask the runtime to quit.
                        api.prevent_close();
                        let _ = handle.hide();
                    }
                });
                window
            }
        };
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
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
                                tauri::async_runtime::block_on(state.stop.runtime_operation())?;
                            #[cfg(target_os = "macos")]
                            operation.check_request()?;
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
                                tauri::async_runtime::block_on(prepare_native(app.clone(), false))?;
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
                            exit = Some(match reason {
                                NativeExitReason::Shutdown => CommonFinish::Quit,
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
                                    tauri::async_runtime::block_on(state.stop.runtime_operation())?
                                        .restart_proof(&state.host)?;
                                    CommonFinish::Restart
                                }
                                NativeExitReason::RuntimeSwitch => {
                                    if !state.host.runtime_restart_ready().map_err(|_| {
                                        io::Error::other("runtime switch unavailable")
                                    })? {
                                        return Err(io::Error::other("runtime switch not ready"));
                                    }
                                    CommonFinish::Restart
                                }
                            });
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
        let sent = write_native_frame(&mut stream, response_tag, &response);
        // Once validated, explicit shutdown/restart still owns a closed reply.
        if let Some(reason) = exit {
            tauri::async_runtime::block_on(state.finish(app, reason));
            return;
        }
        if sent.is_err() {
            break;
        }
        #[cfg(target_os = "macos")]
        if let Some(endpoint) = storage_endpoint {
            if crate::macos_storage::send_endpoint(&mut stream, &endpoint).is_err() {
                break;
            }
        }
    }
    // Intentional termination leaves the active transition in control through
    // helper acknowledgement and durable journal completion. Unsolicited EOF
    // still needs ordered finish; neither kind of EOF is a helper stop receipt.
    if state.stop.exit_owner.finish_on_native_eof() {
        tauri::async_runtime::block_on(state.finish(app, CommonFinish::RuntimeFailure));
    }
}
async fn engine_exchange(state: &CommonState, body: &[u8]) -> io::Result<Vec<u8>> {
    let request: Request = serde_json::from_slice(body)?;
    if matches!(request, Request::Start { .. })
        || cfg!(target_os = "macos")
            && matches!(&request, Request::Redundant { request, .. } if request.is_start())
    {
        state
            .host
            .before_native_tunnel_start()
            .await
            .map_err(|_| io::Error::other("common start rejected"))?;
    }
    let mut operation = state.stop.runtime_operation().await?;
    // A bound capability query can create an engine.
    // It must share the start fence and cannot reuse an earlier stop receipt.
    if matches!(request, Request::Start { .. } | Request::RebindUdp { .. })
        || cfg!(any(windows, target_os = "linux", target_os = "macos"))
            && (matches!(request, Request::Version { .. })
                || matches!(&request, Request::Redundant { request, .. } if request.is_start()))
    {
        operation.begin_start(
            state
                .host
                .native_start_blocked()
                .map_err(|_| io::Error::other("update state unavailable"))?
                || (cfg!(any(windows, target_os = "linux"))
                    && state
                        .host
                        .runtime_switch_blocks_native_start()
                        .map_err(|_| io::Error::other("runtime switch state unavailable"))?)
                || !runtime_is_alive(state),
        )?;
    }
    #[cfg(target_os = "macos")]
    {
        operation
            .exchange_request(state.stop.tunnel.transport(), request)
            .await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let response = state
            .stop
            .tunnel
            .transport()
            .exchange(request)
            .await
            .map_err(|_| io::Error::other("engine unavailable"))?;
        serde_json::to_vec(&response).map_err(Into::into)
    }
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
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "macos")]
pub(crate) async fn handoff_macos_installation<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    proof: nelomai_client_container::UpdateStopProof,
    install: impl std::future::Future<Output = Result<(), nelomai_client_updater::UpdateBackendError>>
        + Send
        + 'static,
) -> Result<(), nelomai_client_updater::UpdateBackendError> {
    use nelomai_client_updater::UpdateBackendError;
    let state = app
        .try_state::<Arc<CommonState>>()
        .ok_or_else(|| UpdateBackendError::new("update_stop_proof_unavailable"))?
        .inner()
        .clone();
    let app = app.clone();
    let mut operation = state.stop.operation.clone().lock_owned().await;
    // Retain ordering even if the request waiter disappears during authorization.
    // No old runtime command may invalidate the stop receipt while its bundle moves.
    crate::macos_launch::run_update(async move {
        let validate = |operation: &NativeOperationState| {
            let current = state.host.update_stop_proof(
                proof.target(),
                nelomai_client_container::UpdateJournalPhase::LocalStopped,
            );
            if !operation.observed_helper_stop
                || operation.replacement.as_ref() != Some(&(proof.clone(), false))
                || current.as_ref().ok() != Some(&proof)
            {
                return Err(UpdateBackendError::new("update_stop_proof_changed"));
            }
            Ok(())
        };
        validate(&operation)?;
        install
            .await
            .map_err(|_| UpdateBackendError::new("update_install_failed"))?;
        // OS replacement and its validated journal receipt are separate facts:
        // even a later proof error must never send the old broker to the new helper.
        operation.broker_replaced = true;
        validate(&operation)?;
        operation.replacement = Some((proof, true));
        // The exact LocalStopped proof is durable and no Start can pass the held
        // native gate. Reap only our owned runtime; do not ask the new dispatcher
        // to authenticate a broker whose bundle has just been moved away.
        let mut was_finishing = None;
        let finish = crate::macos_launch::finish_update(
            async {
                was_finishing = Some(state.finishing.swap(true, Ordering::AcqRel));
                state.stop.stop_after_installation().await
            },
            || {
                crate::macos_launch::prepare_restart_after_exit(Path::new(
                    "/Library/Application Support/Nelomai/common/Nelomai.app",
                ))
            },
            || {
                operation.exit_requested = true;
                state.finishing.store(true, Ordering::Release);
                app.exit(0);
            },
        )
        .await;
        if finish.is_err() {
            if let Some(previous) = was_finishing {
                state.finishing.store(previous, Ordering::Release);
            }
        }
        // If arming the relaunch or reaping the child failed, keep the installed
        // result for existing manual Restart/EOF handling. Never reinterpret a
        // completed replacement as installer failure/cancellation.
        Ok(())
    })
    .await
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
async fn prepare_native(app: tauri::AppHandle, allow_install: bool) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let result = platform::unix::prepare_tunnel(app, allow_install).await;
    #[cfg(windows)]
    let result = {
        let _ = (app, allow_install);
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
enum PreAuthHandoff {
    Continue,
    #[cfg(target_os = "macos")]
    Complete,
    #[cfg(unix)]
    Declined(io::Error),
}

enum PreAuthFailure {
    CommonExecutableUnavailable,
    #[cfg(windows)]
    CommonExecutableUntrusted,
    #[cfg(unix)]
    CandidateLayoutRejected,
    #[cfg(unix)]
    InstalledLayoutRejected,
    #[cfg(unix)]
    InstallationPlanUnavailable,
    #[cfg(target_os = "linux")]
    InstallerInputUnavailable,
    #[cfg(unix)]
    InstallationFailed,
    #[cfg(unix)]
    InstalledCommonUntrusted,
    #[cfg(unix)]
    RelaunchFailed,
}

impl PreAuthFailure {
    fn code(self) -> &'static str {
        match self {
            Self::CommonExecutableUnavailable => "common_executable_unavailable",
            #[cfg(windows)]
            Self::CommonExecutableUntrusted => "common_executable_untrusted",
            #[cfg(unix)]
            Self::CandidateLayoutRejected => "candidate_layout_rejected",
            #[cfg(unix)]
            Self::InstalledLayoutRejected => "installed_layout_rejected",
            #[cfg(unix)]
            Self::InstallationPlanUnavailable => "installation_plan_unavailable",
            #[cfg(target_os = "linux")]
            Self::InstallerInputUnavailable => "installer_input_unavailable",
            #[cfg(unix)]
            Self::InstallationFailed => "installation_failed",
            #[cfg(unix)]
            Self::InstalledCommonUntrusted => "installed_common_untrusted",
            #[cfg(unix)]
            Self::RelaunchFailed => "relaunch_failed",
        }
    }
}

fn pre_auth_handoff() -> Result<PreAuthHandoff, PreAuthFailure> {
    use PreAuthFailure as Failure;

    let original = std::env::current_exe().map_err(|_| Failure::CommonExecutableUnavailable)?;
    #[cfg(windows)]
    nelomai_client_container::desktop::verify_protected_path(&original)
        .map_err(|_| Failure::CommonExecutableUntrusted)?;
    #[cfg(unix)]
    let executable =
        std::fs::canonicalize(original).map_err(|_| Failure::CommonExecutableUnavailable)?;
    #[cfg(target_os = "macos")]
    {
        let source = executable
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .ok_or(Failure::CandidateLayoutRejected)?;
        let installed = Path::new("/Library/Application Support/Nelomai/common/Nelomai.app");
        let installed_exe = installed.join("Contents/MacOS/nelomai-app");
        let candidate = verify_layout(&source.join("Contents/Resources/runtime"))
            .map_err(|_| Failure::CandidateLayoutRejected)?;
        let existing = if installed.exists() {
            Some(
                verify_layout(&installed.join("Contents/Resources/runtime"))
                    .map_err(|_| Failure::InstalledLayoutRejected)?,
            )
        } else {
            None
        };
        let protected = protected_executable(&installed_exe)
            && existing
                .as_ref()
                .is_some_and(|runtime| protected_executable(runtime.executable()));
        let action = macos_installation_action(
            candidate.manifest(),
            existing.as_ref().map(|runtime| runtime.manifest()),
            protected,
            &executable,
            installed,
        )
        .map_err(|_| Failure::InstallationPlanUnavailable)?;
        if action == InstallationAction::Continue {
            return Ok(PreAuthHandoff::Continue);
        }
        if action != InstallationAction::LaunchInstalled {
            if action == InstallationAction::InstallCandidate && existing.is_some() {
                if let Err(error) =
                    crate::macos_launch::require_closed_before_replacement(installed)
                {
                    if error.kind() == io::ErrorKind::WouldBlock {
                        let error = crate::macos_launch::show_replacement_notice()
                            .err()
                            .unwrap_or(error);
                        return Ok(PreAuthHandoff::Declined(error));
                    }
                    return Err(Failure::InstallationPlanUnavailable);
                }
            }
            if !run_macos_pre_auth_installer(&mut macos_installer_command(
                action,
                source,
                installed,
                unsafe { libc::getuid() },
            ))
            .map_err(|_| Failure::InstallationFailed)?
            {
                return Ok(PreAuthHandoff::Declined(io::Error::other(
                    "common installation cancelled",
                )));
            }
        }
        if !protected_executable(&installed_exe) {
            return Err(Failure::InstalledCommonUntrusted);
        }
        verify_layout(&installed.join("Contents/Resources/runtime"))
            .map_err(|_| Failure::InstalledLayoutRejected)?;
        crate::macos_launch::launch_application(installed).map_err(|_| Failure::RelaunchFailed)?;
        Ok(PreAuthHandoff::Complete)
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
            .ok_or(Failure::CandidateLayoutRejected)?;
        let source_resources = source_dir.join("usr/lib/Nelomai");
        let candidate = verify_layout(&source_resources.join("runtime"))
            .map_err(|_| Failure::CandidateLayoutRejected)?;
        let existing = if installed_resources.join("runtime").exists() {
            Some(
                verify_layout(&installed_resources.join("runtime"))
                    .map_err(|_| Failure::InstalledLayoutRejected)?,
            )
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
        )
        .map_err(|_| Failure::InstallationPlanUnavailable)?;
        if action == InstallationAction::Continue {
            return Ok(PreAuthHandoff::Continue);
        }
        if action != InstallationAction::LaunchInstalled {
            let archive = if action == InstallationAction::RepairInstalled {
                installed.join("Nelomai.AppImage")
            } else {
                PathBuf::from(
                    std::env::var_os("APPIMAGE").ok_or(Failure::InstallerInputUnavailable)?,
                )
            };
            let installed_script = installed.join("install-common-linux.sh");
            let candidate_script = source_resources.join("install-common-linux.sh");
            let sha = nelomai_contracts::dispatcher::file_digest(&archive)
                .map_err(|_| Failure::InstallerInputUnavailable)?;
            if !linux_installation::run(
                &installed_script,
                &candidate_script,
                &archive,
                &sha,
                |command| {
                    platform::unix::installer_status(command)
                        .map_err(|_| io::Error::other("common installation failed"))
                },
            )
            .map_err(|_| Failure::InstallationFailed)?
            {
                return Ok(PreAuthHandoff::Declined(io::Error::other(
                    "common installation cancelled",
                )));
            }
        }
        if !protected_executable(&installed_exe) {
            return Err(Failure::InstalledCommonUntrusted);
        }
        verify_layout(&installed_resources.join("runtime"))
            .map_err(|_| Failure::InstalledLayoutRejected)?;
        let _ = std::process::Command::new(installed.join("AppDir/AppRun"))
            .env("APPIMAGE", installed.join("Nelomai.AppImage"))
            .env("APPDIR", installed.join("AppDir"))
            .exec();
        Err(Failure::RelaunchFailed)
    }
    #[cfg(windows)]
    Ok(PreAuthHandoff::Continue)
}

#[cfg(test)]
mod lifecycle_tests {

    fn startup_switch_identities() -> (
        nelomai_contracts::dispatcher::EngineIdentity,
        nelomai_contracts::dispatcher::EngineIdentity,
    ) {
        use nelomai_contracts::{dispatcher as d, RuntimeSlot};

        let target = d::EngineIdentity {
            slot: RuntimeSlot::Latest,
            runtime_version: "0.4.2".into(),
            runtime_contract_version: 1,
            container_version: "0.4.2".into(),
            manifest_sha256: "a".repeat(64),
        };
        let source = d::EngineIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.3.11".into(),
            ..target.clone()
        };
        (source, target)
    }

    #[test]
    fn startup_retires_only_the_verified_source_and_requires_its_stop_ack() {
        use nelomai_contracts::dispatcher as d;
        let (source, target) = startup_switch_identities();
        let mut foreign = source.clone();
        foreign.manifest_sha256 = "b".repeat(64);
        for (reported, running, ack, expected_stop, succeeds) in [
            (
                &source,
                true,
                d::DispatcherResponse::success(source.clone(), false),
                true,
                true,
            ),
            (
                &source,
                false,
                d::DispatcherResponse::success(source.clone(), false),
                true,
                true,
            ),
            (
                &source,
                true,
                d::DispatcherResponse::success(source.clone(), true),
                true,
                false,
            ),
            (
                &source,
                true,
                d::DispatcherResponse::success(target.clone(), false),
                true,
                false,
            ),
            (&target, true, d::DispatcherResponse::failure(), false, true),
            (
                &foreign,
                true,
                d::DispatcherResponse::failure(),
                false,
                false,
            ),
        ] {
            let mut calls = 0;
            let result = retire_startup_engine(&source, &target, |request| {
                calls += 1;
                match (calls, request) {
                    (
                        1,
                        d::DispatcherRequest::Version {
                            contract_version: 1,
                        },
                    ) => Ok(d::DispatcherResponse::success(reported.clone(), running)),
                    (
                        2,
                        d::DispatcherRequest::Stop {
                            contract_version: 1,
                            identity,
                        },
                    ) => {
                        assert_eq!(identity, &source);
                        Ok(ack.clone())
                    }
                    _ => panic!("unexpected dispatcher request"),
                }
            });
            assert_eq!(result.is_ok(), succeeds);
            assert_eq!(calls, 1 + usize::from(expected_stop));
        }
    }

    #[test]
    fn startup_stop_rechecks_identity_after_temporary_error() {
        use nelomai_contracts::dispatcher as d;
        let (source, target) = startup_switch_identities();
        let mut foreign = source.clone();
        foreign.manifest_sha256 = "b".repeat(64);

        for (temporary_error, observed, expected_calls, succeeds) in [
            (io::ErrorKind::TimedOut, &source, 4, true),
            (io::ErrorKind::TimedOut, &target, 3, true),
            (io::ErrorKind::TimedOut, &foreign, 3, false),
            (io::ErrorKind::WouldBlock, &source, 4, true),
        ] {
            let mut calls = 0;
            let result = retire_startup_engine(&source, &target, |request| {
                calls += 1;
                match (calls, request) {
                    (1, d::DispatcherRequest::Version { .. }) => {
                        Ok(d::DispatcherResponse::success(source.clone(), true))
                    }
                    (2, d::DispatcherRequest::Stop { identity, .. }) => {
                        assert_eq!(identity, &source);
                        Err(temporary_error.into())
                    }
                    (3, d::DispatcherRequest::Version { .. }) => {
                        Ok(d::DispatcherResponse::success(observed.clone(), false))
                    }
                    (4, d::DispatcherRequest::Stop { identity, .. }) => {
                        assert_eq!(observed, &source);
                        assert_eq!(identity, &source);
                        Ok(d::DispatcherResponse::success(source.clone(), false))
                    }
                    _ => panic!("unexpected dispatcher request after timeout"),
                }
            });
            assert_eq!(result.is_ok(), succeeds);
            assert_eq!(calls, expected_calls);
        }
    }

    #[test]
    fn startup_stop_retries_end_after_repeated_timeouts() {
        use nelomai_contracts::dispatcher as d;
        let (source, target) = startup_switch_identities();
        let mut calls = 0;
        let error = retire_startup_engine(&source, &target, |request| {
            calls += 1;
            match (calls, request) {
                (1, d::DispatcherRequest::Version { .. }) => {
                    Ok(d::DispatcherResponse::success(source.clone(), true))
                }
                (2, d::DispatcherRequest::Stop { .. })
                | (3..=4, d::DispatcherRequest::Version { .. }) => {
                    Err(io::ErrorKind::TimedOut.into())
                }
                _ => panic!("startup retry exceeded its request budget"),
            }
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(calls, 4);
    }

    use super::*;
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn pending_installer_rejects_native_frames_without_losing_channel_after_cancel() {
        use nelomai_client_container::desktop::{read_native_frame, write_native_frame};
        use std::{sync::atomic::AtomicUsize, time::Duration};
        struct Transport(AtomicUsize);
        #[async_trait::async_trait]
        impl ServiceTransport for Transport {
            async fn exchange(
                &self,
                _: Request,
            ) -> Result<nelomai_unix_service::Response, nelomai_unix_service::ServiceError>
            {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(nelomai_unix_service::Response::success(None))
            }
        }
        let operation = Arc::new(tokio::sync::Mutex::new(NativeOperationState::default()));
        let stop = Arc::new(stop_fixture(operation.clone()));
        // Authorization is still pending: the installer owns the actual gate.
        let installation = operation.lock_owned().await;
        let transport = Arc::new(Transport(AtomicUsize::new(0)));
        let (stream, mut peer) = NativeStream::pair().unwrap();
        let client = Arc::new(crate::runtime::NativeClient::new(stream).unwrap());
        let worker = {
            let transport = transport.clone();
            std::thread::spawn(move || {
                // Real framed channel and native request boundary; only the
                // privileged service response is synthetic, with counted calls.
                for _ in 0..2 {
                    let (tag, body) = read_native_frame(&mut peer).unwrap();
                    assert_eq!(tag, 1);
                    let request = serde_json::from_slice(&body).unwrap();
                    let reply = tauri::async_runtime::block_on(async {
                        stop.runtime_operation()
                            .await?
                            .exchange_request(&*transport, request)
                            .await
                    });
                    match reply {
                        Ok(body) => write_native_frame(&mut peer, tag, &body).unwrap(),
                        Err(_) => {
                            write_native_frame(&mut peer, 255, b"common operation failed").unwrap()
                        }
                    }
                }
            })
        };
        let pending = {
            let client = client.clone();
            tokio::spawn(async move {
                client
                    .exchange(1, serde_json::to_vec(&Request::status()).unwrap())
                    .await
            })
        };
        let mut pending = pending;
        let while_authorizing =
            tokio::time::timeout(Duration::from_millis(500), &mut pending).await;
        assert_eq!(transport.0.load(Ordering::SeqCst), 0);
        // User cancels; release the unchanged broker, even on the RED path.
        drop(installation);
        if while_authorizing.is_err() {
            let _ = pending.await;
        }
        let after_cancel = client
            .exchange(1, serde_json::to_vec(&Request::status()).unwrap())
            .await;
        worker.join().unwrap();
        assert!(
            matches!(while_authorizing, Ok(Ok(Err(_)))),
            "native IPC must reject promptly while installer owns the gate"
        );
        assert!(
            after_cancel.is_ok(),
            "Cancel must leave the same native channel usable"
        );
        assert_eq!(transport.0.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "macos")]
    fn stop_fixture(operation: Arc<tokio::sync::Mutex<NativeOperationState>>) -> NativeStop {
        let root = tempfile::tempdir().unwrap();
        NativeStop {
            child: Mutex::new(None),
            exit_owner: Default::default(),
            tunnel: Arc::new(nelomai_unix_service::UnixTunnelController::new(
                nelomai_unix_service::UnixSocketTransport::new(
                    root.path().join("old-update-helper.sock"),
                ),
            )),
            operation,
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn failed_relaunch_keeps_stop_receipt_sealed_against_late_logout() {
        let operation = Arc::new(tokio::sync::Mutex::new(NativeOperationState {
            broker_replaced: true,
            observed_helper_stop: true,
            exit_requested: false,
            ..Default::default()
        }));
        let stop = stop_fixture(operation.clone());
        assert!(matches!(
            stop.stop_local().await,
            Err(BrokerError::RecoveryRequired)
        ));
        assert!(
            operation.lock().await.observed_helper_stop,
            "installed receipt must survive Stop even when auto relaunch was not armed"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn completed_update_can_finish_after_native_eof_already_claimed_shutdown() {
        let operation = Arc::new(tokio::sync::Mutex::new(NativeOperationState {
            broker_replaced: true,
            observed_helper_stop: true,
            ..Default::default()
        }));
        let stop = stop_fixture(operation);
        assert!(stop.exit_owner.finish_on_native_eof());
        stop.stop_after_installation()
            .await
            .expect("verified update must finish despite earlier EOF ownership");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn queued_engine_requests_never_reach_replacement_helper() {
        use std::sync::atomic::AtomicUsize;
        struct Transport(AtomicUsize);
        #[async_trait::async_trait]
        impl ServiceTransport for Transport {
            async fn exchange(
                &self,
                _: Request,
            ) -> Result<nelomai_unix_service::Response, nelomai_unix_service::ServiceError>
            {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(nelomai_unix_service::Response::success(None))
            }
        }
        for request in [Request::stop(), Request::status(), Request::version()] {
            let transport = Arc::new(Transport(AtomicUsize::new(0)));
            let operation = Arc::new(tokio::sync::Mutex::new(NativeOperationState::default()));
            let mut installation = operation.lock().await;
            let queued = {
                let operation = operation.clone();
                let transport = transport.clone();
                tokio::spawn(async move {
                    operation
                        .lock()
                        .await
                        .exchange_request(&*transport, request)
                        .await
                })
            };
            tokio::task::yield_now().await;
            assert!(!queued.is_finished());
            installation.broker_replaced = true;
            drop(installation);
            assert!(
                queued.await.unwrap().is_err(),
                "old request must be rejected after replacement"
            );
            assert_eq!(transport.0.load(Ordering::SeqCst), 0);
        }
        let transport = Transport(AtomicUsize::new(0));
        NativeOperationState::default()
            .exchange_request(&transport, Request::status())
            .await
            .unwrap();
        assert_eq!(
            transport.0.load(Ordering::SeqCst),
            1,
            "ordinary helper requests remain available"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn queued_stop_cannot_invalidate_receipt_after_update_exit_is_requested() {
        let root = tempfile::tempdir().unwrap();
        let operation = Arc::new(tokio::sync::Mutex::new(NativeOperationState {
            observed_helper_stop: true,
            ..Default::default()
        }));
        let stop = Arc::new(NativeStop {
            child: Mutex::new(None),
            exit_owner: Default::default(),
            tunnel: Arc::new(nelomai_unix_service::UnixTunnelController::new(
                nelomai_unix_service::UnixSocketTransport::new(root.path().join("replaced.sock")),
            )),
            operation: operation.clone(),
        });
        let mut installation = operation.lock().await;
        let waiter = tokio::spawn(async move { stop.stop_local().await });
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "installer must retain native ordering"
        );
        installation.exit_requested = true;
        drop(installation);
        assert!(matches!(
            waiter.await.unwrap(),
            Err(BrokerError::RecoveryRequired)
        ));
        assert!(
            operation.lock().await.observed_helper_stop,
            "a late Stop must not erase the verified update stop receipt"
        );
    }

    #[tokio::test]
    async fn common_stop_receipt_and_queued_native_start_require_completed_native_operations() {
        #[cfg(target_os = "macos")]
        for fault in [
            "unbound",
            "pending",
            "scoped_error",
            "stale_scope",
            "final_error",
            "none",
            "cancel_waiter",
        ] {
            use nelomai_client_tunnel::redundancy::{
                protocol::Snapshot,
                session::{SessionPhase, SessionState},
                SessionScope, Slot,
            };
            use nelomai_contracts::{dispatcher as d, RuntimeSlot};
            use nelomai_unix_service::{Response, ServiceTunnelState};
            use std::{
                io::Write,
                os::unix::net::{UnixListener, UnixStream},
            };

            let root = tempfile::tempdir().unwrap();
            let paths = [
                root.path().join("lifecycle.sock"),
                root.path().join("private.sock"),
            ];
            let identity = d::EngineIdentity {
                slot: RuntimeSlot::Latest,
                runtime_version: "test".into(),
                runtime_contract_version: 1,
                container_version: "test".into(),
                manifest_sha256: "ab".repeat(32),
            };
            let scope = SessionScope {
                runtime: RuntimeSlot::Latest,
                runtime_generation: 10,
                session_id: "11111111-1111-4111-8111-111111111111".into(),
                connection_generation: 3,
            };
            let mut native = Snapshot {
                session: SessionState::new(scope, Slot::A, 1, 1).unwrap().snapshot(),
                leases: [None, None],
                current_leases: [None, None],
                primary_ready: false,
                standby_ready: false,
                standby_failed: false,
                stalled: false,
                cleanup_pending: false,
                retirement_pending: false,
                warm_stop_v1: false,
            };
            native.session.phase = SessionPhase::Stopped;
            let calls = Arc::new(Mutex::new(Vec::new()));
            let done = Arc::new(AtomicBool::new(false));
            let mut threads = Vec::new();
            let entered = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
            for (index, path) in paths.iter().enumerate() {
                let listener = UnixListener::bind(path).unwrap();
                let calls = calls.clone();
                let done = done.clone();
                let identity = identity.clone();
                let native = native.clone();
                let entered = entered.clone();
                let release = release.clone();
                threads.push(std::thread::spawn(move || {
                    for stream in listener.incoming() {
                        if done.load(Ordering::Acquire) {
                            break;
                        }
                        let mut stream = stream.unwrap();
                        stream
                            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                            .unwrap();
                        let input = d::read_frame(&mut stream, d::MAX_ENGINE_FRAME).unwrap();
                        let value: serde_json::Value = serde_json::from_slice(
                            d::frame_body(&input, d::MAX_ENGINE_FRAME).unwrap(),
                        )
                        .unwrap();
                        let output = if index == 0 {
                            let label = value["command"].as_str().unwrap();
                            calls.lock().unwrap().push(format!("dispatcher:{label}"));
                            let reply = if label == "stop" && fault == "final_error" {
                                d::DispatcherResponse::failure()
                            } else {
                                d::DispatcherResponse::success(identity.clone(), label != "stop")
                            };
                            d::encode_frame(&reply).unwrap()
                        } else {
                            let label = value["request"]["action"]
                                .as_str()
                                .or_else(|| value["command"].as_str())
                                .unwrap();
                            calls.lock().unwrap().push(format!("engine:{label}"));
                            if label == "status" && fault == "cancel_waiter" {
                                entered.notify_one();
                                let (lock, wake) = &*release;
                                let guard = lock.lock().unwrap();
                                let _guard = wake
                                    .wait_timeout_while(
                                        guard,
                                        std::time::Duration::from_secs(3),
                                        |released| !*released,
                                    )
                                    .unwrap();
                            }
                            let mut reply = Response::success(Some(ServiceTunnelState::Stopped));
                            let mut snapshot = native.clone();
                            if label == "stop" {
                                if fault == "scoped_error" {
                                    reply = Response::failure("scoped_stop_failed");
                                } else if fault == "stale_scope" {
                                    snapshot.session.scope.connection_generation += 1;
                                } else if fault == "pending" {
                                    snapshot.cleanup_pending = true;
                                }
                            }
                            reply.redundancy = Some(snapshot);
                            nelomai_unix_service::encode_response(&reply).unwrap()
                        };
                        stream.write_all(&output).unwrap();
                    }
                }));
            }
            let binding = d::CommonEngineBinding::default();
            if fault != "unbound" {
                binding.bind(identity).unwrap();
            }
            let stop = Arc::new(NativeStop {
                child: Mutex::new(None),
                exit_owner: Default::default(),
                tunnel: Arc::new(nelomai_unix_service::UnixTunnelController::new(
                    nelomai_unix_service::UnixSocketTransport::with_dispatcher(
                        &paths[1], &paths[0],
                    )
                    .for_common(binding),
                )),
                operation: Arc::new(tokio::sync::Mutex::new(NativeOperationState {
                    observed_helper_stop: true,
                    ..Default::default()
                })),
            });
            let result = if fault == "cancel_waiter" {
                let worker = {
                    let stop = stop.clone();
                    tokio::spawn(async move { stop.stop_local().await })
                };
                tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
                    .await
                    .unwrap();
                worker.abort();
                assert!(worker.await.unwrap_err().is_cancelled());
                assert!(
                    stop.operation.try_lock().is_err(),
                    "cancelled waiter must not release native ordering"
                );
                *release.0.lock().unwrap() = true;
                release.1.notify_all();
                let operation =
                    tokio::time::timeout(std::time::Duration::from_secs(2), stop.operation.lock())
                        .await
                        .unwrap();
                assert!(operation.observed_helper_stop);
                Ok(())
            } else {
                stop.stop_local().await
            };
            done.store(true, Ordering::Release);
            for path in paths {
                let _ = UnixStream::connect(path);
            }
            for thread in threads {
                thread.join().unwrap();
            }
            assert_eq!(
                result.is_ok(),
                matches!(fault, "none" | "cancel_waiter"),
                "{fault}"
            );
            assert_eq!(
                stop.operation.lock().await.observed_helper_stop,
                matches!(fault, "none" | "cancel_waiter"),
                "{fault}"
            );
            let mut expected = vec!["dispatcher:version", "engine:status"];
            if fault != "unbound" {
                expected.extend(["dispatcher:version", "engine:stop"]);
                if matches!(fault, "none" | "cancel_waiter") || fault == "final_error" {
                    expected.extend(["dispatcher:version", "dispatcher:stop"]);
                }
            }
            assert_eq!(*calls.lock().unwrap(), expected, "{fault}");
        }
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
