use nelomai_desktop_helper_spike::{authorize_peer, peer_uid, HelperRequest, HelperResponse};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

fn main() -> io::Result<()> {
    let allowed_uid = unsafe { libc::geteuid() };
    let socket_path = socket_path();
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;

    let (mut stream, _) = listener.accept()?;
    authorize_peer(peer_uid(&stream)?, allowed_uid)?;

    let mut request = String::new();
    stream.read_to_string(&mut request)?;
    let response = match serde_json::from_str::<HelperRequest>(&request) {
        Ok(_request) => HelperResponse {
            ok: true,
            message: "authorized local request".to_string(),
        },
        Err(error) => HelperResponse {
            ok: false,
            message: format!("invalid request: {error}"),
        },
    };
    serde_json::to_writer(&mut stream, &response)?;
    stream.flush()?;
    std::fs::remove_file(socket_path)?;
    Ok(())
}

fn socket_path() -> PathBuf {
    std::env::temp_dir().join(format!("nelomai-helper-spike-{}.sock", std::process::id()))
}
