use nelomai_contracts::dispatcher::{
    Installation, MutationGuard, ProcessDispatcher, RealInstallIo,
};
use nelomai_unix_service::{
    bind_listener, prepare_runtime_directory, run_timed_engine_channel, serve_dispatcher_one,
    PlatformBackend, ServiceError, TunnelRequestHandler, DEFAULT_SOCKET_PATH,
    DISPATCHER_SOCKET_PATH,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
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
    // The verified broker policy belongs to this installed dispatcher. Keep
    // a copy for temporary lifecycle replies while the engine lock is held.
    #[cfg(target_os = "linux")]
    let broker = dispatcher.layout.broker.clone();
    let dispatcher = Arc::new(Mutex::new(dispatcher));
    let private_owner = Arc::clone(&dispatcher);
    std::thread::spawn(move || {
        let mut failures = DispatcherFailureLog::default();
        loop {
            match serve_dispatcher_one(&private, &private_owner, true) {
                Ok(()) => failures.success(),
                Err(error) => {
                    if failures.should_log(&error, Instant::now()) {
                        log_dispatcher_failure("private", &error);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    });
    let mut failures = DispatcherFailureLog::default();
    loop {
        #[cfg(target_os = "linux")]
        let result =
            nelomai_unix_service::serve_dispatcher_lifecycle_one(&lifecycle, &dispatcher, &broker);
        #[cfg(target_os = "macos")]
        let result = serve_dispatcher_one(&lifecycle, &dispatcher, false);
        match result {
            Ok(()) => failures.success(),
            Err(error) => {
                if failures.should_log(&error, Instant::now()) {
                    log_dispatcher_failure("lifecycle", &error);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

#[derive(Default)]
struct DispatcherFailureLog {
    consecutive: u64,
    denied_at: BTreeMap<&'static str, Instant>,
}

impl DispatcherFailureLog {
    fn success(&mut self) {
        self.consecutive = 0;
    }

    fn should_log(&mut self, error: &ServiceError, now: Instant) -> bool {
        if let ServiceError::BrokerRejected(reason) = error {
            let code = reason.code();
            if self.denied_at.get(code).is_some_and(|previous| {
                now.saturating_duration_since(*previous) < Duration::from_secs(60)
            }) {
                return false;
            }
            self.denied_at.insert(code, now);
            return true;
        }
        self.consecutive = self.consecutive.saturating_add(1);
        self.consecutive == 1 || self.consecutive % 100 == 0
    }
}

fn log_dispatcher_failure(channel: &'static str, error: &ServiceError) {
    if let ServiceError::BrokerRejected(reason) = error {
        eprintln!("{channel} dispatcher broker rejected: {}", reason.code());
    } else {
        eprintln!("{channel} dispatcher request failed: {}", error.code());
    }
}

#[cfg(test)]
#[test]
fn first_occurrence_of_each_broker_denial_survives_other_consecutive_failures() {
    use nelomai_contracts::dispatcher::BrokerDenial;

    let mut failures = DispatcherFailureLog::default();
    let now = Instant::now();
    let generic = ServiceError::InvalidRequest;
    let uid = ServiceError::BrokerRejected(BrokerDenial::UidMismatch);
    let path = ServiceError::BrokerRejected(BrokerDenial::PathMismatch);
    assert!(failures.should_log(&generic, now));
    assert!(!failures.should_log(&generic, now));
    assert!(failures.should_log(&uid, now));
    assert!(failures.should_log(&path, now));
    assert!(!failures.should_log(&uid, now));
    failures.success();
    assert!(!failures.should_log(&path, now));
    assert!(failures.should_log(&generic, now));
    assert!(failures.should_log(&uid, now + Duration::from_secs(60)));
}

fn run_engine(root: &Path) -> std::io::Result<()> {
    let installation = Installation::production(root)?;
    let layout = installation.load_engine(&std::fs::canonicalize(std::env::current_exe()?)?)?;
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
    // Persistent privileged state, never selected by a product request. DNS
    // service changes survive reboot, so their rollback journal must too. Do
    // not chmod an existing directory: the factory rejects foreign/insecure
    // state instead of adopting it. The existing engine-owner lock serializes
    // both ordinary and pair ownership through this composite backend.
    use std::os::unix::fs::DirBuilderExt;
    let pair_root = root.join("redundancy");
    match std::fs::DirBuilder::new().mode(0o700).create(&pair_root) {
        Ok(()) => std::fs::File::open(root)?.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    let factory = nelomai_unix_service::member_network::runtime::NativePairFactory::new(
        &pair_root,
        layout.identity.slot,
        &directory,
    )?;
    let backend = nelomai_unix_service::member_network::actor::CompositeBackend::new(
        layout.identity.slot,
        backend,
        factory,
    )
    .map_err(|_| nelomai_contracts::dispatcher::blocked())?;
    run_timed_engine_channel(
        std::io::stdin(),
        &mut std::io::stdout().lock(),
        &mut TunnelRequestHandler::new(backend, layout.identity.runtime_version),
    )
}
