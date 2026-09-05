use nelomai_contracts::dispatcher::{
    Installation, MutationGuard, ProcessDispatcher, RealInstallIo,
};
use nelomai_unix_service::{
    bind_listener, prepare_runtime_directory, run_engine_channel, serve_dispatcher_one,
    PlatformBackend, TunnelRequestHandler, DEFAULT_SOCKET_PATH, DISPATCHER_SOCKET_PATH,
};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[cfg(target_os = "linux")]
const INSTALL_ROOT: &str = "/usr/local/libexec/nelomai";
#[cfg(target_os = "macos")]
const INSTALL_ROOT: &str = "/Library/PrivilegedHelperTools/ru.nelomai.tunnel";

fn main() {
    if let Err(error) = run() {
        eprintln!("nelomai helper failed: {error}");
        std::process::exit(1);
    }
}
fn run() -> std::io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(std::io::Error::other("helper must run as root"));
    }
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [mode, source, broker, uid] if mode == "install-layout" => {
            let owner = uid
                .to_str()
                .ok_or_else(nelomai_contracts::dispatcher::blocked)?;
            if owner
                .parse::<u32>()
                .ok()
                .filter(|value| *value > 0)
                .is_none()
            {
                return Err(nelomai_contracts::dispatcher::blocked());
            }
            let layout = Installation::production(Path::new(INSTALL_ROOT))?.install(
                Path::new(source),
                Path::new(broker),
                owner,
                &RealInstallIo,
            )?;
            println!("{}", layout.dispatcher_path().display());
            Ok(())
        }
        [mode, root] if mode == "--engine-mode" => run_engine(Path::new(root)),
        [mode, published, previous] if mode == "rollback-layout" => {
            let published = published
                .to_str()
                .ok_or_else(nelomai_contracts::dispatcher::blocked)?;
            let previous = previous
                .to_str()
                .ok_or_else(nelomai_contracts::dispatcher::blocked)?;
            Installation::production(Path::new(INSTALL_ROOT))?.rollback_activation(
                published,
                if previous.is_empty() {
                    None
                } else {
                    Some(previous)
                },
            )
        }
        [mode] if mode == "--dispatcher" => run_dispatcher(Path::new(INSTALL_ROOT)),
        _ => Err(std::io::Error::other("invalid helper arguments")),
    }
}
fn run_dispatcher(root: &Path) -> std::io::Result<()> {
    prepare_runtime_directory(Path::new("/var/run/nelomai"))?;
    let mut dispatcher = ProcessDispatcher::new(Installation::production(root)?)?;
    nelomai_unix_service::recover_dispatcher(&mut dispatcher)
        .map_err(|_| nelomai_contracts::dispatcher::blocked())?;
    let uid = dispatcher
        .layout
        .broker
        .owner
        .parse::<u32>()
        .map_err(|_| nelomai_contracts::dispatcher::blocked())?;
    if uid == 0 {
        return Err(nelomai_contracts::dispatcher::blocked());
    }
    let private = bind_listener(Path::new(DEFAULT_SOCKET_PATH), uid)?;
    let lifecycle = bind_listener(Path::new(DISPATCHER_SOCKET_PATH), uid)?;
    let dispatcher = Arc::new(Mutex::new(dispatcher));
    let private_owner = Arc::clone(&dispatcher);
    std::thread::spawn(move || loop {
        let _ = serve_dispatcher_one(&private, &private_owner, true);
    });
    loop {
        let _ = serve_dispatcher_one(&lifecycle, &dispatcher, false);
    }
}
fn run_engine(root: &Path) -> std::io::Result<()> {
    let installation = Installation::production(root)?;
    let layout = installation.load()?;
    if std::fs::canonicalize(std::env::current_exe()?)? != layout.engine_path() {
        return Err(nelomai_contracts::dispatcher::blocked());
    }
    let _lease = MutationGuard::at(&root.join("engine-owner.lock"))?;
    let directory: PathBuf = layout
        .engine_path()
        .parent()
        .ok_or_else(nelomai_contracts::dispatcher::blocked)?
        .into();
    #[cfg(target_os = "linux")]
    let backend = PlatformBackend::new(directory.join("amneziawg-go"), "/var/run/nelomai");
    #[cfg(target_os = "macos")]
    let backend = PlatformBackend::new(
        directory.join("wireguard-go"),
        directory.join("amneziawg-go"),
        "/var/run/nelomai",
    );
    let backend = backend.map_err(|_| nelomai_contracts::dispatcher::blocked())?;
    run_engine_channel(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &mut TunnelRequestHandler::new(backend, layout.identity.runtime_version),
    )
}
