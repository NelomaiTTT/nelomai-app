use base64::{engine::general_purpose::STANDARD, Engine};
use ipnet::IpNet;
use std::fmt;
use std::net::IpAddr;
use thiserror::Error;
use zeroize::Zeroizing;

pub struct SecretKey(Zeroizing<[u8; 32]>);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    port: u16,
}

impl Endpoint {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

pub struct ParsedPeer {
    pub public_key: [u8; 32],
    pub preshared_key: Option<SecretKey>,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Endpoint,
    pub persistent_keepalive: Option<u16>,
}

impl fmt::Debug for ParsedPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedPeer")
            .field("public_key", &"<public key>")
            .field("preshared_key", &self.preshared_key)
            .field("allowed_ips", &self.allowed_ips)
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

pub struct ParsedConfiguration {
    pub private_key: SecretKey,
    pub addresses: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub mtu: Option<u32>,
    pub listen_port: Option<u16>,
    pub peers: Vec<ParsedPeer>,
}

impl fmt::Debug for ParsedConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedConfiguration")
            .field("private_key", &self.private_key)
            .field("addresses", &self.addresses)
            .field("dns", &self.dns)
            .field("mtu", &self.mtu)
            .field("listen_port", &self.listen_port)
            .field("peers", &self.peers)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigurationError {
    #[error("configuration contains an executable directive")]
    UnsafeDirective,
    #[error("configuration structure is invalid")]
    InvalidStructure,
    #[error("configuration value is invalid")]
    InvalidValue,
    #[error("configuration field is unsupported")]
    UnsupportedField,
    #[error("configuration is incomplete")]
    MissingField,
}

impl ConfigurationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsafeDirective => "unsafe_configuration_directive",
            Self::InvalidStructure => "invalid_configuration_structure",
            Self::InvalidValue => "invalid_configuration_value",
            Self::UnsupportedField => "unsupported_configuration_field",
            Self::MissingField => "missing_configuration_field",
        }
    }
}

#[derive(Default)]
struct InterfaceBuilder {
    private_key: Option<SecretKey>,
    addresses: Vec<IpNet>,
    dns: Vec<IpAddr>,
    mtu: Option<u32>,
    listen_port: Option<u16>,
}

#[derive(Default)]
struct PeerBuilder {
    public_key: Option<[u8; 32]>,
    preshared_key: Option<SecretKey>,
    allowed_ips: Vec<IpNet>,
    endpoint: Option<Endpoint>,
    persistent_keepalive: Option<u16>,
}

enum Section {
    None,
    Interface,
    Peer(PeerBuilder),
}

pub fn parse_configuration(input: &str) -> Result<ParsedConfiguration, ConfigurationError> {
    let mut interface = InterfaceBuilder::default();
    let mut peers = Vec::new();
    let mut section = Section::None;

    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match line {
            "[Interface]" => {
                finish_peer(&mut section, &mut peers)?;
                section = Section::Interface;
                continue;
            }
            "[Peer]" => {
                finish_peer(&mut section, &mut peers)?;
                section = Section::Peer(PeerBuilder::default());
                continue;
            }
            _ if line.starts_with('[') => return Err(ConfigurationError::InvalidStructure),
            _ => {}
        }

        let (raw_key, raw_value) = line
            .split_once('=')
            .ok_or(ConfigurationError::InvalidStructure)?;
        let key = raw_key.trim();
        let value = raw_value.trim();
        if value.is_empty() {
            return Err(ConfigurationError::InvalidValue);
        }

        if matches!(
            key,
            "PreUp" | "PostUp" | "PreDown" | "PostDown" | "Table" | "SaveConfig"
        ) {
            return Err(ConfigurationError::UnsafeDirective);
        }

        match &mut section {
            Section::Interface => parse_interface_field(&mut interface, key, value)?,
            Section::Peer(peer) => parse_peer_field(peer, key, value)?,
            Section::None => return Err(ConfigurationError::InvalidStructure),
        }
    }

    finish_peer(&mut section, &mut peers)?;
    let private_key = interface
        .private_key
        .ok_or(ConfigurationError::MissingField)?;
    if interface.addresses.is_empty() || peers.is_empty() {
        return Err(ConfigurationError::MissingField);
    }

    Ok(ParsedConfiguration {
        private_key,
        addresses: interface.addresses,
        dns: interface.dns,
        mtu: interface.mtu,
        listen_port: interface.listen_port,
        peers,
    })
}

fn parse_interface_field(
    interface: &mut InterfaceBuilder,
    key: &str,
    value: &str,
) -> Result<(), ConfigurationError> {
    match key {
        "PrivateKey" if interface.private_key.is_none() => {
            interface.private_key = Some(SecretKey(Zeroizing::new(parse_key(value)?)));
        }
        "Address" if interface.addresses.is_empty() => {
            interface.addresses = parse_list(value)?;
        }
        "DNS" if interface.dns.is_empty() => {
            interface.dns = parse_list(value)?;
        }
        "MTU" if interface.mtu.is_none() => {
            let mtu = value
                .parse::<u32>()
                .map_err(|_| ConfigurationError::InvalidValue)?;
            if !(576..=65_535).contains(&mtu) {
                return Err(ConfigurationError::InvalidValue);
            }
            interface.mtu = Some(mtu);
        }
        "ListenPort" if interface.listen_port.is_none() => {
            interface.listen_port = Some(parse_nonzero_port(value)?);
        }
        "PrivateKey" | "Address" | "DNS" | "MTU" | "ListenPort" => {
            return Err(ConfigurationError::InvalidStructure);
        }
        _ => return Err(ConfigurationError::UnsupportedField),
    }
    Ok(())
}

fn parse_peer_field(
    peer: &mut PeerBuilder,
    key: &str,
    value: &str,
) -> Result<(), ConfigurationError> {
    match key {
        "PublicKey" if peer.public_key.is_none() => {
            peer.public_key = Some(parse_key(value)?);
        }
        "PresharedKey" if peer.preshared_key.is_none() => {
            peer.preshared_key = Some(SecretKey(Zeroizing::new(parse_key(value)?)));
        }
        "AllowedIPs" if peer.allowed_ips.is_empty() => {
            peer.allowed_ips = parse_list(value)?;
        }
        "Endpoint" if peer.endpoint.is_none() => {
            peer.endpoint = Some(parse_endpoint(value)?);
        }
        "PersistentKeepalive" if peer.persistent_keepalive.is_none() => {
            peer.persistent_keepalive = Some(
                value
                    .parse::<u16>()
                    .map_err(|_| ConfigurationError::InvalidValue)?,
            );
        }
        "PublicKey" | "PresharedKey" | "AllowedIPs" | "Endpoint" | "PersistentKeepalive" => {
            return Err(ConfigurationError::InvalidStructure)
        }
        _ => return Err(ConfigurationError::UnsupportedField),
    }
    Ok(())
}

fn finish_peer(
    section: &mut Section,
    peers: &mut Vec<ParsedPeer>,
) -> Result<(), ConfigurationError> {
    let Section::Peer(peer) = std::mem::replace(section, Section::None) else {
        return Ok(());
    };

    peers.push(ParsedPeer {
        public_key: peer.public_key.ok_or(ConfigurationError::MissingField)?,
        preshared_key: peer.preshared_key,
        allowed_ips: if peer.allowed_ips.is_empty() {
            return Err(ConfigurationError::MissingField);
        } else {
            peer.allowed_ips
        },
        endpoint: peer.endpoint.ok_or(ConfigurationError::MissingField)?,
        persistent_keepalive: peer.persistent_keepalive,
    });
    Ok(())
}

fn parse_key(value: &str) -> Result<[u8; 32], ConfigurationError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| ConfigurationError::InvalidValue)?;
    decoded
        .try_into()
        .map_err(|_| ConfigurationError::InvalidValue)
}

fn parse_list<T: std::str::FromStr>(value: &str) -> Result<Vec<T>, ConfigurationError> {
    value
        .split(',')
        .map(str::trim)
        .map(|entry| {
            if entry.is_empty() {
                Err(ConfigurationError::InvalidValue)
            } else {
                entry.parse().map_err(|_| ConfigurationError::InvalidValue)
            }
        })
        .collect()
}

fn parse_nonzero_port(value: &str) -> Result<u16, ConfigurationError> {
    let port = value
        .parse::<u16>()
        .map_err(|_| ConfigurationError::InvalidValue)?;
    if port == 0 {
        Err(ConfigurationError::InvalidValue)
    } else {
        Ok(port)
    }
}

fn parse_endpoint(value: &str) -> Result<Endpoint, ConfigurationError> {
    let (host, port) = if let Some(value) = value.strip_prefix('[') {
        let (host, port) = value
            .split_once("]:")
            .ok_or(ConfigurationError::InvalidValue)?;
        (host, port)
    } else {
        value
            .rsplit_once(':')
            .ok_or(ConfigurationError::InvalidValue)?
    };
    if host.is_empty()
        || host.chars().any(char::is_whitespace)
        || host.contains('/')
        || host.contains('\\')
    {
        return Err(ConfigurationError::InvalidValue);
    }

    Ok(Endpoint {
        host: host.to_string(),
        port: parse_nonzero_port(port)?,
    })
}
