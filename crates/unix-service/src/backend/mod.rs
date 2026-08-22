#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use crate::{Awg3Parameters, ParsedConfiguration, ServiceError, ServiceTunnelState};
use base64::{engine::general_purpose::STANDARD, Engine};
use defguard_wireguard_rs::{
    host::Host, key::Key, net::IpAddrMask, peer::Peer, InterfaceConfiguration,
};
use nelomai_client_tunnel::TunnelTransport;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "macos")]
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
pub use linux::LinuxBackend as PlatformBackend;
#[cfg(target_os = "macos")]
pub use macos::MacosBackend as PlatformBackend;

pub(crate) struct BackendConfiguration {
    pub interface: InterfaceConfiguration,
    #[cfg(target_os = "macos")]
    pub endpoints: Vec<SocketAddr>,
}

pub(crate) struct RebindPeer {
    public_key_hex: String,
    persistent_keepalive_interval: u16,
}

const MAX_DIAGNOSTIC_EVENTS: usize = 96;
const MAX_DIAGNOSTIC_BYTES: usize = 48 * 1024;
const MAX_USERSPACE_LOG_BYTES: usize = 32 * 1024;
const USERSPACE_LOG_FILE: &str = "userspace-tunnel.log";

#[derive(Default)]
pub(crate) struct DiagnosticJournal {
    entries: VecDeque<String>,
    bytes: usize,
}

impl DiagnosticJournal {
    pub(crate) fn record(&mut self, event: &str, detail: &str) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let event = single_line(event);
        let detail = single_line(detail);
        let entry = if detail.is_empty() {
            format!("timestamp_epoch_millis={timestamp} event={event}")
        } else {
            format!("timestamp_epoch_millis={timestamp} event={event} {detail}")
        };
        self.bytes = self.bytes.saturating_add(entry.len());
        self.entries.push_back(entry);
        while self.entries.len() > MAX_DIAGNOSTIC_EVENTS || self.bytes > MAX_DIAGNOSTIC_BYTES {
            let Some(removed) = self.entries.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(removed.len());
        }
    }

    pub(crate) fn render(&self, snapshot: &str) -> String {
        let mut output = String::from("[nelomai.unix_helper.snapshot]\n");
        output.push_str(snapshot.trim_end());
        output.push_str("\n[nelomai.unix_helper.events]\n");
        for entry in &self.entries {
            output.push_str(entry);
            output.push('\n');
        }
        output
    }
}

pub(crate) fn transport_name(transport: Option<TunnelTransport>) -> &'static str {
    match transport {
        Some(TunnelTransport::WireGuard) => "wireguard",
        Some(TunnelTransport::AmneziaWg3) => "amnezia_wg3",
        None => "none",
    }
}

pub(crate) fn state_name(state: ServiceTunnelState) -> &'static str {
    match state {
        ServiceTunnelState::Stopped => "stopped",
        ServiceTunnelState::Starting => "starting",
        ServiceTunnelState::Running => "running",
        ServiceTunnelState::Stopping => "stopping",
        ServiceTunnelState::Failed => "failed",
    }
}

pub(crate) fn host_diagnostic_snapshot(host: &Host) -> String {
    let received_bytes = host
        .peers
        .values()
        .fold(0u64, |total, peer| total.saturating_add(peer.rx_bytes));
    let sent_bytes = host
        .peers
        .values()
        .fold(0u64, |total, peer| total.saturating_add(peer.tx_bytes));
    let latest_handshake_epoch_millis = host
        .peers
        .values()
        .filter_map(|peer| peer.last_handshake)
        .filter_map(|handshake| handshake.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis())
        .filter(|timestamp| *timestamp > 0)
        .max()
        .map_or_else(|| "none".to_string(), |value| value.to_string());
    format!(
        "uapi=ok\nlisten_port={}\npeers={}\nreceived_bytes={received_bytes}\nsent_bytes={sent_bytes}\nlatest_handshake_epoch_millis={latest_handshake_epoch_millis}",
        host.listen_port,
        host.peers.len(),
    )
}

pub(crate) fn userspace_log_streams(runtime_directory: &Path) -> Option<(Stdio, Stdio)> {
    let file = open_userspace_log(runtime_directory).ok()?;
    let (reader, stdout) = UnixStream::pair().ok()?;
    let stderr = stdout.try_clone().ok()?;
    thread::Builder::new()
        .name("nelomai-tunnel-log".to_string())
        .spawn(move || collect_userspace_log(reader, file))
        .ok()?;
    let stdout: OwnedFd = stdout.into();
    let stderr: OwnedFd = stderr.into();
    Some((Stdio::from(stdout), Stdio::from(stderr)))
}

fn open_userspace_log(runtime_directory: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(runtime_directory.join(USERSPACE_LOG_FILE))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

fn collect_userspace_log(mut input: UnixStream, mut file: File) {
    let mut retained = Vec::with_capacity(MAX_USERSPACE_LOG_BYTES);
    let mut chunk = [0_u8; 8 * 1024];
    let mut writable = true;
    loop {
        let read = match input.read(&mut chunk) {
            Ok(0) => return,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        retained.extend_from_slice(&chunk[..read]);
        let overflow = retained.len().saturating_sub(MAX_USERSPACE_LOG_BYTES);
        if overflow > 0 {
            retained.drain(..overflow);
        }
        if writable
            && (file.set_len(0).is_err()
                || file.seek(SeekFrom::Start(0)).is_err()
                || file.write_all(&retained).is_err()
                || file.flush().is_err())
        {
            // Keep draining the stream even when the diagnostic file becomes unavailable,
            // otherwise a full socket buffer could block the tunnel process while it logs.
            writable = false;
        }
    }
}

pub(crate) fn append_userspace_log(output: &mut String, runtime_directory: &Path) {
    output.push_str("[nelomai.userspace_tunnel.log]\n");
    match read_userspace_log_tail(runtime_directory) {
        Ok(log) if !log.is_empty() => output.push_str(&log),
        Ok(_) => output.push_str("empty\n"),
        Err(error) => {
            output.push_str("unavailable code=");
            output.push_str(error.code());
            output.push('\n');
        }
    }
}

fn read_userspace_log_tail(runtime_directory: &Path) -> Result<String, ServiceError> {
    let mut file = File::open(runtime_directory.join(USERSPACE_LOG_FILE))
        .map_err(|_| ServiceError::Backend("userspace_log_unavailable".to_string()))?;
    let length = file
        .metadata()
        .map_err(|_| ServiceError::Backend("userspace_log_unavailable".to_string()))?
        .len();
    let offset = length.saturating_sub(MAX_USERSPACE_LOG_BYTES as u64);
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| ServiceError::Backend("userspace_log_unavailable".to_string()))?;
    let mut bytes = Vec::with_capacity((length - offset) as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| ServiceError::Backend("userspace_log_unavailable".to_string()))?;
    let mut log = String::from_utf8_lossy(&bytes).replace('\0', "");
    if offset > 0 {
        if let Some(newline) = log.find('\n') {
            log.drain(..=newline);
        }
    }
    if !log.ends_with('\n') && !log.is_empty() {
        log.push('\n');
    }
    Ok(log)
}

fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '_'
            }
        })
        .take(512)
        .collect()
}

pub(crate) fn rebind_peers_from_configuration(
    configuration: &ParsedConfiguration,
) -> Vec<RebindPeer> {
    configuration
        .peers
        .iter()
        .map(|peer| RebindPeer {
            public_key_hex: Key::new(peer.public_key).to_lower_hex(),
            persistent_keepalive_interval: peer.persistent_keepalive.unwrap_or(0),
        })
        .collect()
}

pub(crate) fn rebind_peers_from_host(host: &Host) -> Vec<RebindPeer> {
    host.peers
        .values()
        .map(|peer| RebindPeer {
            public_key_hex: peer.public_key.to_lower_hex(),
            persistent_keepalive_interval: peer.persistent_keepalive_interval.unwrap_or(0),
        })
        .collect()
}

pub(crate) fn build_backend_configuration(
    configuration: &ParsedConfiguration,
) -> Result<BackendConfiguration, ServiceError> {
    #[cfg(target_os = "macos")]
    let mut endpoints = Vec::with_capacity(configuration.peers.len());
    let mut peers = Vec::with_capacity(configuration.peers.len());

    for source in &configuration.peers {
        let endpoint = (source.endpoint.host(), source.endpoint.port())
            .to_socket_addrs()
            .map_err(|_| ServiceError::InvalidConfiguration)?
            .next()
            .ok_or(ServiceError::InvalidConfiguration)?;
        #[cfg(target_os = "macos")]
        endpoints.push(endpoint);

        let mut peer = Peer::new(Key::new(source.public_key));
        peer.preshared_key = source
            .preshared_key
            .as_ref()
            .map(|key| Key::new(*key.as_bytes()));
        peer.endpoint = Some(endpoint);
        peer.persistent_keepalive_interval = source.persistent_keepalive;
        peer.allowed_ips = source
            .allowed_ips
            .iter()
            .map(|network| IpAddrMask::new(network.addr(), network.prefix_len()))
            .collect();
        peers.push(peer);
    }

    Ok(BackendConfiguration {
        interface: InterfaceConfiguration {
            name: String::new(),
            prvkey: STANDARD.encode(configuration.private_key.as_bytes()),
            addresses: configuration
                .addresses
                .iter()
                .map(|network| IpAddrMask::new(network.addr(), network.prefix_len()))
                .collect(),
            port: configuration.listen_port.unwrap_or(0),
            peers,
            mtu: configuration.mtu,
            fwmark: None,
        },
        #[cfg(target_os = "macos")]
        endpoints,
    })
}

const USERSPACE_SOCKET_TIMEOUT: Duration = Duration::from_secs(3);
const USERSPACE_SOCKET_DIRECTORY: &str = "/var/run/wireguard";

pub(crate) fn userspace_socket_path(interface_name: &str) -> PathBuf {
    Path::new(USERSPACE_SOCKET_DIRECTORY).join(format!("{interface_name}.sock"))
}

pub(crate) fn apply_awg3_configuration(
    interface_name: &str,
    parameters: &Awg3Parameters,
) -> Result<(), ServiceError> {
    let mut socket = UnixStream::connect(userspace_socket_path(interface_name))
        .map_err(|_| ServiceError::Backend("amneziawg_uapi_unavailable".to_string()))?;
    socket
        .set_read_timeout(Some(USERSPACE_SOCKET_TIMEOUT))
        .and_then(|_| socket.set_write_timeout(Some(USERSPACE_SOCKET_TIMEOUT)))
        .map_err(|_| ServiceError::Backend("amneziawg_uapi_unavailable".to_string()))?;
    let configuration = parameters.uapi_configuration();
    socket
        .write_all(b"set=1\n")
        .and_then(|_| socket.write_all(configuration.as_bytes()))
        .and_then(|_| socket.write_all(b"\n"))
        .map_err(|_| ServiceError::Backend("amneziawg_configuration_failed".to_string()))?;

    if read_awg3_response(socket)? {
        Ok(())
    } else {
        Err(ServiceError::Backend(
            "amneziawg_configuration_failed".to_string(),
        ))
    }
}

pub(crate) fn rebind_userspace_udp(
    interface_name: &str,
    peers: &[RebindPeer],
) -> Result<(), ServiceError> {
    if peers.is_empty() {
        return Err(ServiceError::Backend("udp_rebind_failed".to_string()));
    }
    let mut socket = UnixStream::connect(userspace_socket_path(interface_name))
        .map_err(|_| ServiceError::Backend("amneziawg_uapi_unavailable".to_string()))?;
    socket
        .set_read_timeout(Some(USERSPACE_SOCKET_TIMEOUT))
        .and_then(|_| socket.set_write_timeout(Some(USERSPACE_SOCKET_TIMEOUT)))
        .map_err(|_| ServiceError::Backend("amneziawg_uapi_unavailable".to_string()))?;
    let request = rebind_uapi_configuration(peers);
    socket
        .write_all(request.as_bytes())
        .map_err(|_| ServiceError::Backend("udp_rebind_failed".to_string()))?;
    if read_awg3_response(socket)? {
        Ok(())
    } else {
        Err(ServiceError::Backend("udp_rebind_failed".to_string()))
    }
}

fn rebind_uapi_configuration(peers: &[RebindPeer]) -> String {
    let mut request = String::from("set=1\nlisten_port=0\n");
    for peer in peers {
        let keepalive = peer.persistent_keepalive_interval;
        let (first, second) = if keepalive == 0 {
            (1, 0)
        } else {
            (0, keepalive)
        };
        for interval in [first, second] {
            request.push_str("public_key=");
            request.push_str(&peer.public_key_hex);
            request.push_str("\nupdate_only=true\npersistent_keepalive_interval=");
            request.push_str(&interval.to_string());
            request.push('\n');
        }
    }
    request.push('\n');
    request
}

pub(crate) fn verify_awg3_configuration(
    interface_name: &str,
    parameters: &Awg3Parameters,
) -> Result<bool, ServiceError> {
    let mut socket = UnixStream::connect(userspace_socket_path(interface_name))
        .map_err(|_| ServiceError::Backend("amneziawg_uapi_unavailable".to_string()))?;
    socket
        .set_read_timeout(Some(USERSPACE_SOCKET_TIMEOUT))
        .and_then(|_| socket.set_write_timeout(Some(USERSPACE_SOCKET_TIMEOUT)))
        .map_err(|_| ServiceError::Backend("amneziawg_uapi_unavailable".to_string()))?;
    socket
        .write_all(b"get=1\n\n")
        .map_err(|_| ServiceError::Backend("amneziawg_configuration_failed".to_string()))?;
    read_awg3_configuration(socket, parameters)
}

pub(crate) fn apply_and_verify_awg3_configuration(
    interface_name: &str,
    parameters: &Awg3Parameters,
) -> Result<(), ServiceError> {
    apply_awg3_configuration(interface_name, parameters)?;
    if verify_awg3_configuration(interface_name, parameters)? {
        return Ok(());
    }

    apply_awg3_configuration(interface_name, parameters)?;
    verify_awg3_configuration(interface_name, parameters)?
        .then_some(())
        .ok_or_else(|| ServiceError::Backend("amneziawg_profile_mismatch".to_string()))
}

pub(crate) fn configure_interface_after_awg3<ApplyAwg3, ConfigureInterface>(
    parameters: Option<&Awg3Parameters>,
    apply_awg3: ApplyAwg3,
    configure_interface: ConfigureInterface,
) -> Result<(), ServiceError>
where
    ApplyAwg3: FnOnce(&Awg3Parameters) -> Result<(), ServiceError>,
    ConfigureInterface: FnOnce() -> Result<(), ServiceError>,
{
    if let Some(parameters) = parameters {
        apply_awg3(parameters)?;
    }
    configure_interface()
}

fn read_awg3_configuration(
    socket: UnixStream,
    parameters: &Awg3Parameters,
) -> Result<bool, ServiceError> {
    let expected = parameters.uapi_configuration();
    let expected_lines = expected.lines().collect::<Vec<_>>();
    let mut matched = vec![false; expected_lines.len()];
    let mut reader = BufReader::new(socket);

    loop {
        let mut line = zeroize::Zeroizing::new(String::new());
        let read = reader
            .read_line(&mut line)
            .map_err(|_| ServiceError::Backend("amneziawg_configuration_failed".to_string()))?;
        if read == 0 || line.as_str() == "\n" {
            return Ok(false);
        }
        let value = line.trim_end_matches(['\r', '\n']);
        if value == "errno=0" {
            let mut terminator = String::new();
            reader
                .read_line(&mut terminator)
                .map_err(|_| ServiceError::Backend("amneziawg_configuration_failed".to_string()))?;
            return Ok(terminator == "\n" && matched.into_iter().all(|value| value));
        }

        let Some((key, _)) = value.split_once('=') else {
            continue;
        };
        if let Some(index) = expected_lines.iter().position(|expected| {
            expected.starts_with(key) && expected.as_bytes().get(key.len()) == Some(&b'=')
        }) {
            if expected_lines[index] != value {
                return Ok(false);
            }
            matched[index] = true;
        }
    }
}

fn read_awg3_response(socket: UnixStream) -> Result<bool, ServiceError> {
    let mut reader = BufReader::new(socket);
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|_| ServiceError::Backend("amneziawg_configuration_failed".to_string()))?;
        if read == 0 || line == "\n" {
            return Ok(false);
        }
        if line.trim() == "errno=0" {
            let mut terminator = String::new();
            reader
                .read_line(&mut terminator)
                .map_err(|_| ServiceError::Backend("amneziawg_configuration_failed".to_string()))?;
            return Ok(terminator == "\n");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_configuration;
    use std::os::unix::fs::PermissionsExt;

    const PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const PUBLIC_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    #[test]
    fn shared_backend_mapping_preserves_tunnel_semantics() {
        let parsed = parse_configuration(&format!(
            "\
[Interface]
PrivateKey = {PRIVATE_KEY}
Address = 10.8.1.2/32
DNS = 8.8.8.8
MTU = 1280

[Peer]
PublicKey = {PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:10001
PersistentKeepalive = 21
"
        ))
        .expect("parse");

        let native = build_backend_configuration(&parsed).expect("map");

        assert_eq!(native.interface.addresses[0].to_string(), "10.8.1.2/32");
        assert_eq!(native.interface.mtu, Some(1280));
        assert_eq!(
            native.interface.peers[0].endpoint,
            Some("127.0.0.1:10001".parse().expect("endpoint"))
        );
        assert_eq!(
            native.interface.peers[0].allowed_ips[0].to_string(),
            "0.0.0.0/0"
        );
        assert_eq!(
            native.interface.peers[0].persistent_keepalive_interval,
            Some(21)
        );
    }

    #[test]
    fn diagnostics_are_bounded_and_userspace_log_is_private() {
        let runtime = tempfile::tempdir().expect("create runtime directory");
        let file = open_userspace_log(runtime.path()).expect("open userspace log");
        let (reader, mut stdout) = UnixStream::pair().expect("create log stream");
        let collector = thread::spawn(move || collect_userspace_log(reader, file));
        let prefix = "discarded-line\n".repeat(4096);
        stdout.write_all(prefix.as_bytes()).expect("write prefix");
        stdout
            .write_all("ERROR: final diagnostic line\n".as_bytes())
            .expect("write final line");
        drop(stdout);
        collector.join().expect("collect userspace log");

        let metadata = std::fs::metadata(runtime.path().join(USERSPACE_LOG_FILE))
            .expect("read userspace log metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert!(metadata.len() <= MAX_USERSPACE_LOG_BYTES as u64);
        let log = read_userspace_log_tail(runtime.path()).expect("read userspace log");
        assert!(log.len() <= MAX_USERSPACE_LOG_BYTES);
        assert!(log.ends_with("ERROR: final diagnostic line\n"));

        let mut journal = DiagnosticJournal::default();
        for index in 0..200 {
            journal.record("probe", &format!("index={index}"));
        }
        let rendered = journal.render("state=running");
        assert!(!rendered.contains("index=0\n"));
        assert!(rendered.contains("index=199\n"));
        assert!(rendered.len() < MAX_DIAGNOSTIC_BYTES + 1024);
    }

    #[test]
    fn awg3_uapi_stops_reading_at_the_protocol_terminator() {
        let (client, mut server_socket) = UnixStream::pair().expect("socket pair");
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");
        let server = thread::spawn(move || {
            server_socket
                .write_all(b"errno=0\n\n")
                .expect("write response");
            thread::sleep(Duration::from_millis(200));
        });
        assert!(read_awg3_response(client).expect("read response"));
        server.join().expect("server");
    }

    #[test]
    fn udp_rebind_rotates_the_socket_and_triggers_an_immediate_keepalive() {
        let parsed = parse_configuration(&format!(
            "[Interface]\nPrivateKey = {PRIVATE_KEY}\nAddress = 10.8.1.2/32\n\n[Peer]\nPublicKey = {PUBLIC_KEY}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:10001\nPersistentKeepalive = 21\n"
        ))
        .expect("parse");
        let peers = rebind_peers_from_configuration(&parsed);

        let request = rebind_uapi_configuration(&peers);

        assert_eq!(
            request,
            "set=1\nlisten_port=0\npublic_key=0101010101010101010101010101010101010101010101010101010101010101\nupdate_only=true\npersistent_keepalive_interval=0\npublic_key=0101010101010101010101010101010101010101010101010101010101010101\nupdate_only=true\npersistent_keepalive_interval=21\n\n"
        );
    }

    #[test]
    fn udp_rebind_uses_a_temporary_keepalive_when_the_peer_has_none() {
        let peer = RebindPeer {
            public_key_hex: Key::new([2; 32]).to_lower_hex(),
            persistent_keepalive_interval: 0,
        };

        let request = rebind_uapi_configuration(&[peer]);

        assert!(request.contains("persistent_keepalive_interval=1\n"));
        assert!(request.ends_with("persistent_keepalive_interval=0\n\n"));
    }

    #[test]
    fn awg3_uapi_verification_requires_the_exact_live_profile() {
        let parsed = parse_configuration(&format!(
            "[Interface]\nPrivateKey = {PRIVATE_KEY}\nAddress = 10.8.1.2/32\nJc = 5\nJmin = 48\nJmax = 192\nS1 = 132\nS2 = 67\nS3 = 28\nS4 = 30\nH1 = 100-120\nH2 = 121\nH3 = 122\nH4 = 123\nHeaderProtectionKey = {PUBLIC_KEY}\nContentPaddingAddition = 0-32\n\n[Peer]\nPublicKey = {PUBLIC_KEY}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:10001\n"
        ))
        .expect("parse");
        let parameters = parsed.awg3.as_ref().expect("AWG3 parameters");
        let expected = parameters.uapi_configuration();
        let response = format!(
            "private_key={}\n{}errno=0\n\n",
            "00".repeat(32),
            expected.as_str()
        );
        let (client, mut server_socket) = UnixStream::pair().expect("socket pair");
        let server = thread::spawn(move || server_socket.write_all(response.as_bytes()));

        assert!(read_awg3_configuration(client, parameters).expect("read response"));
        server.join().expect("server").expect("write response");

        let mismatched = expected.replace("s1=132", "s1=167");
        let response = format!("{mismatched}errno=0\n\n");
        let (client, mut server_socket) = UnixStream::pair().expect("socket pair");
        let server = thread::spawn(move || server_socket.write_all(response.as_bytes()));

        assert!(!read_awg3_configuration(client, parameters).expect("read response"));
        server.join().expect("server").expect("write response");
    }

    #[test]
    fn awg3_profile_is_applied_before_peer_configuration() {
        let parsed = parse_configuration(&format!(
            "[Interface]\nPrivateKey = {PRIVATE_KEY}\nAddress = 10.8.1.2/32\nJc = 5\nJmin = 48\nJmax = 192\nS1 = 132\nS2 = 67\nS3 = 28\nS4 = 30\nH1 = 100\nH2 = 121\nH3 = 122\nH4 = 123\nHeaderProtectionKey = {PUBLIC_KEY}\nContentPaddingAddition = 0-32\n\n[Peer]\nPublicKey = {PUBLIC_KEY}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:10001\n"
        ))
        .expect("parse");
        let events = std::cell::RefCell::new(Vec::new());

        configure_interface_after_awg3(
            parsed.awg3.as_ref(),
            |_| {
                events.borrow_mut().push("awg3");
                Ok(())
            },
            || {
                events.borrow_mut().push("peer");
                Ok(())
            },
        )
        .expect("configure AWG3 interface");

        assert_eq!(events.into_inner(), ["awg3", "peer"]);
    }

    #[test]
    fn awg3_profile_failure_prevents_peer_configuration() {
        let parsed = parse_configuration(&format!(
            "[Interface]\nPrivateKey = {PRIVATE_KEY}\nAddress = 10.8.1.2/32\nJc = 5\nJmin = 48\nJmax = 192\nS1 = 132\nS2 = 67\nS3 = 28\nS4 = 30\nH1 = 100\nH2 = 121\nH3 = 122\nH4 = 123\nHeaderProtectionKey = {PUBLIC_KEY}\nContentPaddingAddition = 0-32\n\n[Peer]\nPublicKey = {PUBLIC_KEY}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:10001\n"
        ))
        .expect("parse");
        let peer_configured = std::cell::Cell::new(false);

        let error = configure_interface_after_awg3(
            parsed.awg3.as_ref(),
            |_| {
                Err(ServiceError::Backend(
                    "amneziawg_configuration_failed".to_string(),
                ))
            },
            || {
                peer_configured.set(true);
                Ok(())
            },
        )
        .expect_err("AWG3 configuration must fail");

        assert_eq!(error.code(), "amneziawg_configuration_failed");
        assert!(!peer_configured.get());
    }
}
