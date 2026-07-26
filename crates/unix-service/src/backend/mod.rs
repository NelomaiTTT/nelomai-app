#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use crate::{ParsedConfiguration, ServiceError};
use base64::{engine::general_purpose::STANDARD, Engine};
use defguard_wireguard_rs::{key::Key, net::IpAddrMask, peer::Peer, InterfaceConfiguration};
#[cfg(target_os = "macos")]
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_configuration;

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
}
