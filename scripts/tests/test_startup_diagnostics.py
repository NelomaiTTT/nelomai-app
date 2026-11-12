"""Exercise the real Rust startup logger without compiling the application."""
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class StartupDiagnosticsTests(unittest.TestCase):
    def test_duplicate_common_cannot_reach_updater_cache_recovery(self):
        container = (ROOT / "src-tauri/src/container.rs").read_text()
        block = container.split("let api = nelomai_client_api::ClientApi::new(PANEL_BASE)?;", 1)[1]
        block = block.split('stage = "native.bind_identity";', 1)[0]
        driver = """
use std::{io, path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}}};
static OWNED: AtomicBool = AtomicBool::new(true);
static RECOVERIES: AtomicUsize = AtomicUsize::new(0);
static SUPPORT_ROOTS: AtomicUsize = AtomicUsize::new(0);
const PANEL_BASE: &str = "fixture";
#[derive(Clone)] struct App;
impl App {
    fn handle(&self) -> &Self { self }
    fn manage(&self, root: support_diagnostics::SupportDataRoot) -> bool {
        assert_eq!(root.0, Path::new("fixture-data"));
        assert_eq!(RECOVERIES.load(Ordering::SeqCst), 0);
        SUPPORT_ROOTS.fetch_add(1, Ordering::SeqCst);
        true
    }
}
mod support_diagnostics { pub struct SupportDataRoot(pub std::path::PathBuf); }
mod nelomai_client_api {
    #[derive(Clone)] pub struct ClientApi;
    impl ClientApi { pub fn new(_: &str) -> std::io::Result<Self> { Ok(Self) } }
}
mod nelomai_client_storage {
    pub struct SystemRecordFactory;
    impl SystemRecordFactory { pub fn new(_: &str, _: Option<std::path::PathBuf>) -> Self { Self } }
}
mod nelomai_client_updater { pub trait UpdateBackend {} }
mod platform { pub mod updater {
    pub struct DesktopUpdateBackend;
    impl crate::nelomai_client_updater::UpdateBackend for DesktopUpdateBackend {}
    impl DesktopUpdateBackend {
        pub(crate) fn from_build(_: crate::App, _: crate::nelomai_client_api::ClientApi)
            -> std::io::Result<Self> {
            crate::RECOVERIES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Self)
        }
    }
} }
mod startup { pub fn stage(_: &str) {} }
mod commands { pub fn current_platform() {} }
struct RuntimeClientProfile { platform: (), platform_version: Option<()>, architecture: String }
struct DesktopBackground;
struct HostNativePorts {
    stop: Arc<()>, force: Arc<()>, background: Arc<DesktopBackground>,
    updater: Option<Arc<dyn nelomai_client_updater::UpdateBackend>>,
    storage: Option<()>, relaunch: Option<()>,
}
type HostError = io::Error;
struct PreparedHost {
    owner: Owner,
    #[cfg(target_os = "macos")]
    records: Arc<()>,
}
struct Owner(PathBuf);
impl Owner { fn root(&self) -> &Path { &self.0 } }
fn prepare_host(
    data: &Path, _: &Path, _: Option<&[u8]>, _: &str, _: &str,
    _: impl FnOnce() -> nelomai_client_storage::SystemRecordFactory,
) -> io::Result<PreparedHost> {
    claim_owner(data)
}
#[cfg(target_os = "macos")]
fn prepare_macos_host(data: &Path, _: &Path, _: &[u8]) -> io::Result<PreparedHost> {
    claim_owner(data)
}
fn claim_owner(data: &Path) -> io::Result<PreparedHost> {
    if OWNED.swap(true, Ordering::SeqCst) {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(PreparedHost {
        owner: Owner(data.to_owned()),
        #[cfg(target_os = "macos")]
        records: Arc::new(()),
    })
}
struct CommonHost;
impl CommonHost {
    fn open(
        data: &Path, resources: &Path, key: Option<&[u8]>, platform: &str, architecture: &str,
        records: impl FnOnce() -> nelomai_client_storage::SystemRecordFactory,
        _: nelomai_client_api::ClientApi, _: RuntimeClientProfile, _: HostNativePorts,
    ) -> io::Result<Self> {
        prepare_host(data, resources, key, platform, architecture, records)?;
        Ok(Self)
    }
    fn from_prepared(
        _: PreparedHost, _: nelomai_client_api::ClientApi, _: RuntimeClientProfile, _: HostNativePorts,
    ) -> io::Result<Self> { Ok(Self) }
}
fn launch_common() -> io::Result<()> {
    let app = App;
    let data = PathBuf::from("fixture-data");
    let resources = PathBuf::from("fixture-resources");
    let key = [];
    #[cfg(not(target_os = "macos"))]
    let fallback = None;
    let stop = Arc::new(());
    let stage;
    let api = nelomai_client_api::ClientApi::new(PANEL_BASE)?;
    %s
    Ok(())
}
fn main() {
    assert_eq!(launch_common().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert_eq!(RECOVERIES.load(Ordering::SeqCst), 0, "duplicate Common touched updater cache");
    assert_eq!(SUPPORT_ROOTS.load(Ordering::SeqCst), 0, "duplicate Common registered a diagnostics root");
    OWNED.store(false, Ordering::SeqCst);
    launch_common().unwrap();
    assert_eq!(SUPPORT_ROOTS.load(Ordering::SeqCst), 1);
    assert_eq!(RECOVERIES.load(Ordering::SeqCst), 1);
}
""" % block
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "common_owner.rs"
            binary = root / ("probe.exe" if os.name == "nt" else "probe")
            source.write_text(driver)
            compiled = subprocess.run(
                ["rustc", "--edition=2021", str(source), "-o", str(binary)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_pre_auth_verification_failure_reaches_report_only_setup(self):
        container = (ROOT / "src-tauri/src/container.rs").read_text()
        entry = container.split("pub fn run() {", 1)[1].split(
            "\n    let mut context", 1
        )[0]
        handoff_type = container.split("enum PreAuthHandoff {", 1)[1].split(
            "\nfn pre_auth_handoff(", 1
        )[0]
        # Exercise the real command routing, builder configuration and setup
        # guard with spies for actual host setup, handoff and window creation.
        start = entry.index("                use base64::Engine;")
        end = entry.index("\n            });", start)
        entry = entry[:start] + 'println!("normal setup");\n                Ok(())' + entry[end:]
        driver = """
use std::{io, path::{Path, PathBuf}};
mod startup {
    pub fn stage(_: &str) {}
    pub fn error(_: &str, _: &dyn std::error::Error) {}
    pub fn setup<T>(run: impl FnOnce() -> Result<T, Box<dyn std::error::Error>>)
        -> Result<T, Box<dyn std::error::Error>> { run() }
}
mod semver {
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    pub struct Version;
    impl Version { pub fn parse(_: &str) -> Result<Self, ()> { Ok(Self) } }
}
struct Runtime;
impl Runtime { fn container_version(&self) -> &str { "0.4.2" } }
fn verify_layout(path: &Path) -> io::Result<Runtime> {
    println!("verify");
    if path == Path::new("invalid") { return Err(io::ErrorKind::InvalidData.into()); }
    Ok(Runtime)
}
fn scenario() -> String { std::env::var("PRE_AUTH_SCENARIO").unwrap() }
#[cfg(unix)]
mod libc {
    pub unsafe fn geteuid() -> u32 { u32::from(super::scenario() != "root") }
}
enum PreAuthHandoff {%s
fn pre_auth_handoff() -> Result<PreAuthHandoff, PreAuthFailure> {
    println!("handoff");
    match scenario().as_str() {
        "executable" => Err(PreAuthFailure::CommonExecutableUnavailable),
        #[cfg(windows)]
        "protected path" => Err(PreAuthFailure::CommonExecutableUntrusted),
        #[cfg(unix)]
        "manifest" => Err(PreAuthFailure::CandidateLayoutRejected),
        #[cfg(unix)]
        "installed manifest" => Err(PreAuthFailure::InstalledLayoutRejected),
        #[cfg(unix)]
        "installer failure" => Err(PreAuthFailure::InstallationFailed),
        #[cfg(unix)]
        "relaunch failure" => Err(PreAuthFailure::RelaunchFailed),
        #[cfg(unix)]
        "cancelled" => Ok(PreAuthHandoff::Declined(io::Error::other("cancelled"))),
        #[cfg(target_os = "macos")]
        "notice" => Ok(PreAuthHandoff::Declined(io::ErrorKind::WouldBlock.into())),
        #[cfg(target_os = "macos")]
        "complete" => Ok(PreAuthHandoff::Complete),
        "continue" => Ok(PreAuthHandoff::Continue),
        _ => panic!("unexpected handoff"),
    }
}
mod support_diagnostics {
    #[derive(Default)] pub struct SupportReportState;
}
#[macro_export]
macro_rules! generate_handler {
    ($($name:path),* $(,)?) => { [$(stringify!($name)),*] };
}
mod tauri {
    pub use crate::generate_handler;
    #[derive(Default)] pub struct Builder(Vec<&'static str>);
    impl Builder {
        pub fn plugin(mut self, plugin: &'static str) -> Self { self.0.push(plugin); self }
        pub fn manage(self, _: super::support_diagnostics::SupportReportState) -> Self { self }
        pub fn invoke_handler(self, handlers: [&str; 3]) -> Self {
            assert!(handlers[0].ends_with("app_collect_support_diagnostics"));
            assert!(handlers[1].ends_with("app_save_support_diagnostics"));
            assert!(handlers[2].ends_with("app_send_support_diagnostics"));
            self
        }
        pub fn setup(self, run: impl FnOnce(&mut super::App)
            -> Result<(), Box<dyn std::error::Error>>) -> Self {
            for plugin in &self.0 { println!("plugin {plugin}"); }
            run(&mut super::App).unwrap();
            self
        }
    }
}
mod tauri_plugin_updater {
    pub struct Builder;
    impl Builder {
        pub fn new() -> Self { Self }
        pub fn build(self) -> &'static str { "updater" }
    }
}
mod tauri_plugin_notification { pub fn init() -> &'static str { "notification" } }
mod tauri_plugin_dialog { pub fn init() -> &'static str { "dialog" } }
#[cfg(windows)]
mod tauri_plugin_single_instance {
    pub fn init(_: impl FnOnce(&super::App, (), ())) -> &'static str { "single instance" }
}
#[cfg(windows)]
enum RuntimeAction { Show }
#[cfg(windows)]
fn queue_action(_: &App, _: RuntimeAction) {}
struct App;
impl App { fn handle(&self) -> &Self { self } }
fn show_startup_failure(_: &App, stage: &str, reason: Option<&str>) -> io::Result<()> {
    println!("report {stage} {}", reason.unwrap());
    Ok(())
}
fn main() { %s
}
""" % (handoff_type, entry)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "pre_auth.rs"
            binary = source.with_suffix(".exe" if os.name == "nt" else "")
            source.write_text(driver)
            compiled = subprocess.run(
                ["rustc", "--edition=2021", str(source), "-o", str(binary)],
                env={**os.environ, "CARGO_PKG_VERSION": "0.4.2"}, capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            terminal = [("executable", "common_executable_unavailable")]
            if os.name == "nt":
                terminal.append(("protected path", "common_executable_untrusted"))
            else:
                terminal.extend([
                    ("manifest", "candidate_layout_rejected"),
                    ("installed manifest", "installed_layout_rejected"),
                    ("installer failure", "installation_failed"),
                    ("relaunch failure", "relaunch_failed"),
                ])
            normal_plugins = ["plugin single instance"] if os.name == "nt" else []
            normal_plugins.extend(["plugin updater", "plugin notification", "plugin dialog"])
            cases = [
                (scenario, [], 0, ["handoff", "plugin dialog", f"report common.pre_auth_handoff {reason}"])
                for scenario, reason in terminal
            ] + [
                ("continue", [], 0, ["handoff", *normal_plugins, "normal setup"]),
                ("root", ["--verify-runtime-layout", "valid"], 0, ["verify"]),
                ("root", ["--verify-runtime-layout", "invalid"], 1, ["verify"]),
                ("root", ["--verify-runtime-layout"], 1, []),
            ]
            if os.name != "nt":
                cases.extend([("root", [], 1, []), ("cancelled", [], 1, ["handoff"])])
            if sys.platform == "darwin":
                cases.extend([("complete", [], 0, ["handoff"]), ("notice", [], 1, ["handoff"])])
            for scenario, args, code, output in cases:
                with self.subTest(scenario=scenario, args=args):
                    result = subprocess.run(
                        [str(binary), *args], env={**os.environ, "PRE_AUTH_SCENARIO": scenario},
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, code, result.stderr)
                    self.assertEqual(result.stdout.splitlines(), output)

    @unittest.skipUnless(shutil.which("node"), "Node.js unavailable")
    def test_common_diagnostics_page_has_support_and_interruption_modes(self):
        script = ROOT / "static/startup-failure.js"
        driver = """
const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const source = fs.readFileSync(process.argv[1], "utf8");
for (const hash of ["", "#support", "#interrupted"]) {
  const nodes = new Map();
  const document = {
    addEventListener() {},
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, {
        hidden: false, open: false, textContent: "",
        addEventListener() {},
        show() { this.open = true; },
      });
      return nodes.get(id);
    },
  };
  vm.runInNewContext(source, { document, window: { location: { hash } } });
  const get = document.getElementById;
  assert.equal(get("failure-copy").hidden, hash === "#support");
  assert.equal(get("diagnostics").open, hash === "#support");
  if (hash === "#interrupted") {
    assert.equal(get("failure-title").textContent, "Работа Nelomai прервана");
  }
}
"""
        result = subprocess.run(["node", "--eval", driver, str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_startup_failure_close_preserves_window_until_guarded_exit(self):
        container = (ROOT / "src-tauri/src/container.rs").read_text()
        failure_window = container.split('fn show_startup_failure(', 1)[1]
        handler = failure_window.split('window.on_window_event(move |event| {', 1)[1].split('\n    });', 1)[0]
        queue = container.split("pub(crate) fn queue_action(", 1)[1].split(
            "\npub(crate) fn tray_snapshot", 1
        )[0]
        # The verified child is alive and never polls. Execute the real Close
        # and queue code. A failed guarded stop must leave a retry available.
        driver = '''use std::{any::Any, collections::VecDeque, future::Future,
    sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, AtomicUsize, Ordering}},
    task::{Context, Waker}};
#[derive(Clone)]
struct Handle {
    state: Option<Arc<CommonState>>,
    stage: Option<support_diagnostics::CommonFailureStage>,
    exited: Arc<AtomicBool>,
}
impl Handle {
    fn exit(&self, _: i32) { self.exited.store(true, Ordering::SeqCst); }
    fn get_webview_window(&self, _: &str) -> Option<Window> { None }
    fn try_state<T: 'static>(&self) -> Option<State<'_, T>> {
        let common = self.state.as_ref().and_then(|s| (s as &dyn Any).downcast_ref::<T>());
        let stage = self.stage.as_ref().and_then(|s| (s as &dyn Any).downcast_ref::<T>());
        common.or(stage).map(State)
    }
}
struct State<'a, T>(&'a T);
impl<T> State<'_, T> { fn inner(&self) -> &T { self.0 } }
struct Window;
impl Window {
    fn unminimize(&self) -> Result<(), ()> { Ok(()) }
    fn set_focus(&self) -> Result<(), ()> { Ok(()) }
}
struct Api(Arc<AtomicBool>);
impl Api { fn prevent_close(&self) { self.0.store(true, Ordering::SeqCst); } }
mod tauri {
    pub enum WindowEvent { CloseRequested { api: super::Api }, Other }
    pub(super) type AppHandle = super::Handle;
    pub mod async_runtime {
        use super::super::*;
        pub fn spawn(future: impl Future<Output = ()>) {
            let mut future = std::pin::pin!(future);
            assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_ready());
        }
    }
}
mod support_diagnostics { #[derive(Clone)] pub struct CommonFailureStage; }
enum RuntimeAction { Quit, Show }
enum CommonFinish { Quit }
struct Child;
impl Child { fn exited(&mut self) -> Result<bool, ()> { Ok(false) } }
struct Stop { child: Mutex<Option<Child>> }
struct CommonState {
    stop: Stop,
    runtime_failure_cleanup: OnceLock<bool>,
    actions: Mutex<VecDeque<RuntimeAction>>,
    finish_attempts: AtomicUsize,
}
impl CommonState {
    async fn finish(&self, app: Handle, _: CommonFinish) {
        if self.finish_attempts.fetch_add(1, Ordering::SeqCst) == 1 { app.exit(0); }
    }
}
fn queue_action(%s
fn main() {
    for managed in [true, false] {
        let state = Arc::new(CommonState {
            stop: Stop { child: Mutex::new(Some(Child)) },
            runtime_failure_cleanup: OnceLock::new(),
            actions: Mutex::new(VecDeque::new()),
            finish_attempts: AtomicUsize::new(0),
        });
        let exited = Arc::new(AtomicBool::new(false));
        let handle = Handle {
            state: managed.then(|| state.clone()),
            stage: Some(support_diagnostics::CommonFailureStage),
            exited: exited.clone(),
        };
        let callback = move |event: &tauri::WindowEvent| { %s };
        callback(&tauri::WindowEvent::Other);
        assert!(!exited.load(Ordering::SeqCst));
        for attempt in 1..=2 {
            let prevented = Arc::new(AtomicBool::new(false));
            callback(&tauri::WindowEvent::CloseRequested { api: Api(prevented.clone()) });
            assert!(prevented.load(Ordering::SeqCst), "native close must wait for guarded exit");
            assert_eq!(
                state.finish_attempts.load(Ordering::SeqCst), if managed { attempt } else { 0 },
                "failure window must bypass the live child's poll queue"
            );
            assert!(state.actions.lock().unwrap().is_empty());
            assert_eq!(exited.load(Ordering::SeqCst), !managed || attempt == 2);
        }
    }
}
''' % (queue, handler)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary = root / "close.rs", root / "probe"
            source.write_text(driver)
            compiled = subprocess.run(["rustc", "--edition=2021", str(source), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_eof_distinguishes_unexpected_loss_from_intentional_exit(self):
        container = (ROOT / "src-tauri/src/container.rs").read_text()
        explicit = container.split(
            "        // Once validated, explicit shutdown/restart still owns a closed reply.", 1
        )[1].split("        if sent.is_err()", 1)[0]
        poll = container.split("NativeControl::Poll { presentation } => {", 1)[1].split(
            "                            NativeReply::Actions { actions }", 1
        )[0]
        eof = container.split("    // Intentional termination leaves the active transition", 1)[1]
        eof = eof.split("    if state.stop.exit_owner.finish_on_native_eof()", 1)[1]
        eof = eof.split("\n}\n", 1)[0]
        driver = """use std::{cell::Cell, collections::VecDeque, io, sync::Mutex};
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CommonFinish { Quit, Restart, RuntimeFailure }
mod tauri { pub mod async_runtime {
    pub fn block_on(future: impl std::future::Future<Output = ()>) {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_ready());
    }
} }
struct ExitOwner(bool);
impl ExitOwner { fn finish_on_native_eof(&self) -> bool { self.0 } }
struct Stop { exit_owner: ExitOwner }
#[derive(Default)]
struct Presentation { traffic: String }
struct State {
    stop: Stop, finished: Cell<Option<CommonFinish>>,
    presentation: Mutex<Presentation>, actions: Mutex<VecDeque<()>>,
}
impl State {
    async fn finish(&self, _: (), reason: CommonFinish) {
        self.finished.set(Some(reason));
    }
}
fn legacy_poll(state: &State, presentation: Presentation) -> io::Result<Vec<()>> {
    %s
    Ok(actions)
}
fn native_eof(app: (), state: &State, exit: Option<CommonFinish>) {
    %s
    if state.stop.exit_owner.finish_on_native_eof() %s
}
fn main() {
    for (unsolicited, had_legacy_poll, explicit, expected) in [
        (true, true, None, Some(CommonFinish::RuntimeFailure)),
        (true, false, None, Some(CommonFinish::RuntimeFailure)),
        (false, true, None, None),
        (false, false, None, None),
        (true, false, Some(CommonFinish::Quit), Some(CommonFinish::Quit)),
        (true, true, Some(CommonFinish::Restart), Some(CommonFinish::Restart)),
    ] {
        let state = State {
            stop: Stop { exit_owner: ExitOwner(unsolicited) }, finished: Cell::new(None),
            presentation: Mutex::default(), actions: Mutex::default(),
        };
        if had_legacy_poll {
            assert!(legacy_poll(&state, Presentation::default()).is_ok());
        }
        native_eof((), &state, explicit);
        assert_eq!(state.finished.get(), expected, "unsolicited={unsolicited}, legacy poll={had_legacy_poll}");
    }
}
""" % (poll, explicit, eof)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary = root / "native_eof.rs", root / "probe"
            source.write_text(driver)
            compiled = subprocess.run(["rustc", "--edition=2021", str(source), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_partial_startup_keeps_native_cleanup_available_after_tray_failure(self):
        container = (ROOT / "src-tauri/src/container.rs").read_text()
        tail = container.split('app.manage(state.clone());', 1)[1].split('\n                Ok(())', 1)[0]
        driver = '''use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
static PUMP: AtomicBool = AtomicBool::new(false);
#[derive(Clone)] struct App;
impl App { fn handle(&self) -> &Self { self } }
#[derive(Clone)] struct Host;
impl Host { fn start_update_scheduler(&self) {} }
struct State { host: Host }
mod startup { pub fn stage(_: &str) {} }
mod tauri { pub mod async_runtime {
    // The unrelated scheduler may remain unpolled while native cleanup starts.
    pub fn spawn(_: impl std::future::Future<Output = ()> + Send + 'static) {}
    pub fn spawn_blocking(f: impl FnOnce()) { f(); }
} }
mod desktop { pub fn setup_tray(_: &super::App) -> Result<(), Box<dyn std::error::Error>> {
    Err(std::io::Error::other("synthetic tray unavailable").into())
} }
fn serve_native(_: App, _: Arc<State>, _: ()) { PUMP.store(true, Ordering::SeqCst); }
fn main() {
    let app = &App; let state = Arc::new(State { host: Host }); let native = ();
    let mut stage = "runtime.native_channel";
    let result = (|| -> Result<(), Box<dyn std::error::Error>> { %s Ok(()) })();
    assert!(result.is_err());
    assert_eq!(stage, "common.tray");
    assert!(PUMP.load(Ordering::SeqCst), "fallback Quit must have a live native cleanup pump");
}
''' % tail
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary = root / "partial.rs", root / "probe"
            source.write_text(driver)
            compiled = subprocess.run(["rustc", "--edition=2021", str(source), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_eof_cleanup_keeps_common_alive_until_guarded_close(self):
        container = (ROOT / "src-tauri/src/container.rs").read_text()
        finish = container.split("    async fn finish(", 1)[1].split(
            "        if matches!(reason, CommonFinish::Restart) {", 1
        )[0]
        desktop = (ROOT / "crates/client-container/src/desktop.rs").read_text()
        stop = desktop.split("pub async fn stop_runtime_before_helper(", 1)[1].split(
            "\n/// EOF belongs", 1
        )[0]
        driver = """use std::{io, sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, Ordering}}};
use std::{future::Future, task::{Context, Waker}};
static EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
fn event(value: &'static str) { EVENTS.lock().unwrap().push(value); }
mod tauri {
    pub struct AppHandle;
    impl AppHandle { pub fn exit(&self, _: i32) { super::event("exit"); } }
}
struct VerifiedChild(bool);
impl VerifiedChild {
    fn terminate(&mut self) -> io::Result<()> {
        if !self.0 { event("reap"); self.0 = true; }
        Ok(())
    }
}
mod nelomai_client_container { pub mod desktop {
    use super::super::{io, VerifiedChild};
    fn blocked() -> io::Error { io::Error::other("blocked") }
    pub async fn stop_runtime_before_helper(%s
} }
struct Operation { exit_requested: bool, replacement_verified: bool }
impl Operation {
    async fn lock(&self) -> &Self { self }
    fn restart_proof(&self, _: &()) -> io::Result<()> {
        if self.replacement_verified { Ok(()) } else { Err(io::Error::other("no update")) }
    }
    fn check_request(&self) -> io::Result<()> { Ok(()) }
}
struct Stop { child: Mutex<Option<VerifiedChild>>, tunnel: AtomicBool, operation: Operation }
async fn stop_helper_for_exit(tunnel: &AtomicBool) -> io::Result<()> {
    event("stop_helper");
    if tunnel.load(Ordering::Acquire) { Ok(()) } else { Err(io::Error::other("retry")) }
}
#[derive(Default)]
struct Presentation { disconnect: bool, traffic: String }
enum CommonFinish { Quit, RuntimeFailure }
struct CommonState {
    host: (), stop: Stop, presentation: Mutex<Presentation>,
    finishing: AtomicBool, runtime_failure_cleanup: OnceLock<bool>,
}
fn present_runtime_failure(_: &tauri::AppHandle) { event("show_window"); }
impl CommonState {
    async fn finish(%s
        app.exit(0);
    }
}
fn complete(future: impl Future<Output = ()>) {
    let mut future = std::pin::pin!(future);
    assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_ready());
}
fn main() {
    for (initially_stopped, replacement_verified) in [(true, false), (false, false), (true, true)] {
        EVENTS.lock().unwrap().clear();
        let state = Arc::new(CommonState {
            host: (),
            stop: Stop {
                child: Mutex::new(Some(VerifiedChild(false))),
                tunnel: AtomicBool::new(initially_stopped),
                operation: Operation { exit_requested: false, replacement_verified },
            },
            presentation: Mutex::new(Presentation::default()),
            finishing: AtomicBool::new(false),
            runtime_failure_cleanup: OnceLock::new(),
        });
        complete(state.clone().finish(tauri::AppHandle, CommonFinish::RuntimeFailure));
        if replacement_verified {
            assert_eq!(*EVENTS.lock().unwrap(), ["reap", "exit"]);
            continue;
        }
        assert_eq!(*EVENTS.lock().unwrap(), ["reap", "stop_helper", "show_window"]);
        assert_eq!(state.presentation.lock().unwrap().disconnect, !initially_stopped);
        state.stop.tunnel.store(true, Ordering::Release);
        complete(state.finish(tauri::AppHandle, CommonFinish::Quit));
        let expected = if initially_stopped {
            &["reap", "stop_helper", "show_window", "exit"][..]
        } else {
            &["reap", "stop_helper", "show_window", "stop_helper", "exit"][..]
        };
        assert_eq!(*EVENTS.lock().unwrap(), expected);
    }
}
""" % (stop, finish)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, binary = root / "startup_cleanup.rs", root / "probe"
            source.write_text(driver)
            compiled = subprocess.run(["rustc", "--edition=2021", str(source), "-o", str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_common_setup_failure_is_presented_without_callback_panic(self):
        # Execute the shipping outer setup callback, replacing only the host
        # initialization with a missing-Keychain error and the window with a spy.
        container = (ROOT / "src-tauri/src/container.rs").read_text()
        callback = container.split('.setup(move |app| {', 1)[1].split('\n        });\n    let mut context', 1)[0]
        start = callback.index('startup::setup(|| {')
        end = callback.index('\n            })', start) + len('\n            })')
        callback = callback[:start] + '''startup::setup(|| -> Result<(), Box<dyn std::error::Error>> {
            Err(std::io::Error::other("common auth anchor missing").into())
        })''' + callback[end:]
        module = ROOT / "crates/client-container/src/startup_diagnostics.rs"
        driver = '''#[path = "%s"] mod startup;
use std::sync::atomic::{AtomicUsize, Ordering};
static REPORTED: AtomicUsize = AtomicUsize::new(0);
struct App;
impl App { fn handle(&self) -> &Self { self } }
fn show_startup_failure(_: &App, _: &'static str, reason: Option<&str>) -> std::io::Result<()> {
    assert!(reason.is_none());
    REPORTED.fetch_add(1, Ordering::SeqCst);
    Ok(())
}
fn main() {
    const PRE_AUTH_STAGE: &str = "common.pre_auth_handoff";
    let diagnostics_only = false;
    let pre_auth_reason = None;
    let setup = |app: &mut App| -> Result<(), Box<dyn std::error::Error>> { %s };
    assert!(setup(&mut App).is_ok(), "Tauri panics on Err from its Ready callback");
    assert_eq!(REPORTED.load(Ordering::SeqCst), 1);
}
''' % (module.as_posix(), callback)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "setup.rs"
            binary = root / "probe"
            source.write_text(driver)
            subprocess.run(["rustc", "--edition=2021", str(source), "-o", str(binary)], check=True, capture_output=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_windows_login_admission_platform_wiring(self):
        commands = (ROOT / "src-tauri/src/commands.rs").read_text()
        login = commands.split("pub async fn app_login(", 1)[1].split("#[tauri::command]", 1)[0]
        gate = re.search(r'#\[cfg\(([^]]+)\)\]\s*\{\s*let owner =.*?PrivateRuntimeAuthClient.*?RuntimeStartup.*?\.ensure_ready',
                         login, re.DOTALL).group(1)
        # Compile the actual command's cfg expression, not a copied platform
        # predicate. This is wiring coverage; RuntimeStartup behavior is Rust-tested.
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "login-cfg.rs"
            source.write_text(f'''#[cfg({gate})] fn admits() -> bool {{ true }}
#[cfg(not({gate}))] fn admits() -> bool {{ false }}
fn main() {{ assert!(admits(), "Windows login skipped runtime admission"); }}
''')
            binary = Path(directory) / ("probe.exe" if os.name == "nt" else "probe")
            subprocess.run(["rustc", "--edition=2021", "--cfg", "windows", "--allow",
                            "explicit_builtin_cfgs_in_flags", str(source), "-o", str(binary)],
                           check=True, capture_output=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_diagnostic_build_preserves_stage_and_error_even_on_panic(self):
        self.exercise(True)

    def test_ordinary_build_creates_no_diagnostic_log(self):
        self.exercise(False)

    def test_deferred_setup_records_original_error_before_framework_panic(self):
        self.exercise(True, deferred_setup=True)

    def exercise(self, enabled, deferred_setup=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "probe.rs"
            module = ROOT / "crates/client-container/src/startup_diagnostics.rs"
            driver = '''#[path = %s] mod diagnostics;
fn main() {
    diagnostics::init();
    diagnostics::stage("native.prepare");
    diagnostics::error("native.prepare", &std::io::Error::from_raw_os_error(5));
    panic!("do-not-record-panic-payload");
}
''' % ('"' + module.as_posix() + '"')
            if deferred_setup:
                driver = driver.replace('diagnostics::stage("native.prepare");', '''
    let callback = || diagnostics::setup(|| -> Result<(), Box<dyn std::error::Error>> {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "fixture-storage-denied").into())
    });
    diagnostics::stage("event_loop");
    let result = callback();
    assert_eq!(result.unwrap_err().downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::PermissionDenied);
    diagnostics::stage("native.prepare");''')
            source.write_text(driver)
            binary = root / ("probe.exe" if os.name == "nt" else "probe")
            command = ["rustc", "--edition=2021", str(source), "-o", str(binary)]
            if enabled:
                command += ["--cfg", 'feature="startup-diagnostics"']
            subprocess.run(command, check=True, capture_output=True)
            result = subprocess.run([str(binary)], env={**os.environ, "LOCALAPPDATA": str(root)}, capture_output=True)
            self.assertEqual(result.returncode, 101)
            log = root / "Nelomai/startup-diagnostics.log"
            if enabled:
                self.assertTrue(log.is_file(), "diagnostic build lost the startup failure")
                contents = log.read_text()
                self.assertIn("stage=native.prepare", contents)
                self.assertIn("error stage=native.prepare", contents)
                self.assertIn("panic location=", contents)
                self.assertNotIn("do-not-record-panic-payload", contents)
                if deferred_setup:
                    self.assertIn("error stage=common.setup: fixture-storage-denied", contents)
            else:
                self.assertFalse(log.exists())


if __name__ == "__main__":
    unittest.main()
