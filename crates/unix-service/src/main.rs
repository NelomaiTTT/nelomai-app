use nelomai_unix_service::{
    bind_listener, prepare_runtime_directory, serve_one, ClientPolicy, PlatformBackend,
    TunnelRequestHandler, DEFAULT_SOCKET_PATH,
};
use std::path::PathBuf;

const DEFAULT_RUNTIME_DIRECTORY: &str = "/var/run/nelomai";
#[cfg(target_os = "macos")]
const DEFAULT_WIREGUARD_GO: &str = "/Library/PrivilegedHelperTools/ru.nelomai.tunnel/wireguard-go";

struct Options {
    owner_uid: u32,
    socket: PathBuf,
    runtime_directory: PathBuf,
    #[cfg(target_os = "macos")]
    wireguard_go: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("nelomai tunnel helper failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("helper must run as root".to_string());
    }
    let options = parse_options(std::env::args().skip(1))?;
    if options.owner_uid == 0 {
        return Err("owner uid must identify an unprivileged user".to_string());
    }
    if options.socket.parent() != Some(options.runtime_directory.as_path()) {
        return Err("socket must be located directly in the runtime directory".to_string());
    }

    prepare_runtime_directory(&options.runtime_directory).map_err(generic_io)?;
    let listener = bind_listener(&options.socket, options.owner_uid).map_err(generic_io)?;
    let policy = ClientPolicy {
        owner_uid: options.owner_uid,
    };
    let backend = create_backend(&options)?;
    let mut handler = TunnelRequestHandler::new(backend, env!("CARGO_PKG_VERSION"));

    loop {
        if let Err(error) = serve_one(&listener, &policy, &mut handler) {
            eprintln!("nelomai tunnel helper request failed: {}", error.code());
        }
    }
}

fn parse_options(arguments: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut owner_uid = None;
    let mut socket = PathBuf::from(DEFAULT_SOCKET_PATH);
    let mut runtime_directory = PathBuf::from(DEFAULT_RUNTIME_DIRECTORY);
    #[cfg(target_os = "macos")]
    let mut wireguard_go = PathBuf::from(DEFAULT_WIREGUARD_GO);
    let mut arguments = arguments;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--owner-uid" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "missing owner uid".to_string())?;
                owner_uid = Some(value.parse().map_err(|_| "invalid owner uid".to_string())?);
            }
            "--socket" => {
                socket = absolute_path(arguments.next(), "socket")?;
            }
            "--runtime-directory" => {
                runtime_directory = absolute_path(arguments.next(), "runtime directory")?;
            }
            #[cfg(target_os = "macos")]
            "--wireguard-go" => {
                wireguard_go = absolute_path(arguments.next(), "wireguard-go")?;
            }
            "--version" => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => return Err("unknown helper argument".to_string()),
        }
    }

    Ok(Options {
        owner_uid: owner_uid.ok_or_else(|| "owner uid is required".to_string())?,
        socket,
        runtime_directory,
        #[cfg(target_os = "macos")]
        wireguard_go,
    })
}

fn absolute_path(value: Option<String>, name: &str) -> Result<PathBuf, String> {
    let value = value.ok_or_else(|| format!("missing {name}"))?;
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(format!("{name} must be an absolute path"))
    }
}

#[cfg(target_os = "linux")]
fn create_backend(_options: &Options) -> Result<PlatformBackend, String> {
    PlatformBackend::new().map_err(|error| error.code().to_string())
}

#[cfg(target_os = "macos")]
fn create_backend(options: &Options) -> Result<PlatformBackend, String> {
    PlatformBackend::new(&options.wireguard_go, &options.runtime_directory)
        .map_err(|error| error.code().to_string())
}

fn generic_io(_error: std::io::Error) -> String {
    "helper filesystem setup failed".to_string()
}
