#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use crate::{Awg3Parameters, ParsedConfiguration, ServiceError};
use base64::{engine::general_purpose::STANDARD, Engine};
use defguard_wireguard_rs::{key::Key, net::IpAddrMask, peer::Peer, InterfaceConfiguration};
use std::io::{BufRead, BufReader, Write};
#[cfg(target_os = "macos")]
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(target_os = "linux")]
pub use linux::LinuxBackend as PlatformBackend;
#[cfg(target_os = "macos")]
pub use macos::MacosBackend as PlatformBackend;

pub(crate) struct BackendConfiguration {
    pub interface: InterfaceConfiguration,
    #[cfg(target_os = "macos")]
    pub endpoints: Vec<SocketAddr>,
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
    use std::thread;

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
}
