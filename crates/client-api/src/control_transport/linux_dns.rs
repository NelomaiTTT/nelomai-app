//! Read-only resolved metadata. No DNS packet may be sent before this guard.
use super::super::{DnsServer, Interface};
use serde_json::Value;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};

const SERVICE: &str = "org.freedesktop.resolve1";
const MANAGER: &str = "/org/freedesktop/resolve1";
const MANAGER_IFACE: &str = "org.freedesktop.resolve1.Manager";
const LINK_IFACE: &str = "org.freedesktop.resolve1.Link";

pub(super) fn servers(
    interface: &Interface,
    local: &[IpAddr],
    mut query: impl FnMut(&[&str]) -> io::Result<String>,
) -> io::Result<Vec<DnsServer>> {
    let index = i32::try_from(interface.index)
        .ok()
        .filter(|i| *i > 0)
        .ok_or_else(invalid)?
        .to_string();
    let reply = typed(
        &query(&[
            "--json=short",
            "call",
            SERVICE,
            MANAGER,
            MANAGER_IFACE,
            "GetLink",
            "i",
            &index,
        ])?,
        "o",
    )?;
    let path = reply
        .as_array()
        .filter(|v| v.len() == 1)
        .and_then(|v| v[0].as_str())
        .ok_or_else(invalid)?;
    let suffix = path
        .strip_prefix("/org/freedesktop/resolve1/link/")
        .ok_or_else(invalid)?;
    if suffix.is_empty()
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(invalid());
    }
    for property in ["DNSOverTLS", "DNSSEC"] {
        let global = typed(
            &query(&[
                "--json=short",
                "get-property",
                SERVICE,
                MANAGER,
                MANAGER_IFACE,
                property,
            ])?,
            "s",
        )?;
        let link = typed(
            &query(&[
                "--json=short",
                "get-property",
                SERVICE,
                path,
                LINK_IFACE,
                property,
            ])?,
            "s",
        )?;
        policy(
            property,
            global.as_str().ok_or_else(invalid)?,
            link.as_str().ok_or_else(invalid)?,
        )?;
    }
    let rows = typed(
        &query(&[
            "--json=short",
            "get-property",
            SERVICE,
            path,
            LINK_IFACE,
            "DNSEx",
        ])?,
        "a(iayqs)",
    )?;
    let rows = rows
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 16)
        .ok_or_else(invalid)?;
    let mut result = Vec::new();
    for row in rows {
        let row = row
            .as_array()
            .filter(|v| v.len() == 4)
            .ok_or_else(invalid)?;
        let family = row[0].as_u64().ok_or_else(invalid)?;
        let bytes = row[1]
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(invalid)
            })
            .collect::<io::Result<Vec<_>>>()?;
        let address = match family {
            2 => IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(bytes).map_err(|_| invalid())?,
            )),
            10 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).map_err(|_| invalid())?,
            )),
            _ => return Err(invalid()),
        };
        let port = row[2]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .ok_or_else(invalid)?;
        let sni = row[3].as_str().ok_or_else(invalid)?;
        validate_server(address, port, sni, local)?;
        let address = match address {
            IpAddr::V6(ip) if ip.is_unicast_link_local() => {
                SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, interface.index))
            }
            _ => SocketAddr::new(address, 53),
        };
        if !result
            .iter()
            .any(|server: &DnsServer| server.address == address)
        {
            result.push(DnsServer {
                address,
                interface: interface.clone(),
            });
        }
    }
    Ok(result)
}
fn typed(text: &str, expected: &str) -> io::Result<Value> {
    let mut value: Value = serde_json::from_str(text).map_err(|_| invalid())?;
    if value.get("type").and_then(Value::as_str) != Some(expected) {
        return Err(invalid());
    }
    value.get_mut("data").map(Value::take).ok_or_else(invalid)
}
fn policy(property: &str, global: &str, effective: &str) -> io::Result<()> {
    let known = match property {
        "DNSOverTLS" => matches!(global, "no" | "yes" | "opportunistic"),
        "DNSSEC" => matches!(global, "no" | "yes" | "allow-downgrade"),
        _ => false,
    };
    // Link properties report the effective mode, including inheritance. Only
    // an explicit plaintext/no-validation mode can use this bounded resolver.
    // No downgrade, native resolver retry or OS configuration change is made.
    if !known || effective != "no" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "physical_dns_policy_unsupported",
        ));
    }
    Ok(())
}
fn validate_server(address: IpAddr, port: u16, sni: &str, local: &[IpAddr]) -> io::Result<()> {
    if !matches!(port, 0 | 53) || !sni.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "physical_dns_policy_unsupported",
        ));
    }
    if address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || local.contains(&address)
        || matches!(address,IpAddr::V4(ip) if ip.is_broadcast() || ip.octets()[0]==0 || ip.octets()[0]>=240)
        || matches!(address,IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
    {
        return Err(invalid());
    }
    Ok(())
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "physical_dns_metadata_invalid")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(
        global: &str,
        link: &str,
        dnssec: &str,
        rows: Value,
        local: &[IpAddr],
    ) -> io::Result<Vec<DnsServer>> {
        let interface = Interface {
            index: 2,
            name: "eth0".into(),
            identity: "hardware".into(),
            addresses: vec!["192.0.2.4".parse().unwrap()],
            gateway: None,
        };
        servers(&interface, local, |args| {
            let value = match args {
                ["--json=short", "call", SERVICE, MANAGER, MANAGER_IFACE, "GetLink", "i", "2"] => {
                    serde_json::json!({"type":"o","data":["/org/freedesktop/resolve1/link/_32"]})
                }
                ["--json=short", "get-property", SERVICE, path, iface, property] => {
                    assert!(
                        (*path == MANAGER && *iface == MANAGER_IFACE)
                            || (*path == "/org/freedesktop/resolve1/link/_32"
                                && *iface == LINK_IFACE)
                    );
                    match *property {
                        "DNSOverTLS" => {
                            serde_json::json!({"type":"s","data":if *path==MANAGER {global}else{link}})
                        }
                        "DNSSEC" => serde_json::json!({"type":"s","data":dnssec}),
                        "DNSEx" => {
                            assert_eq!(*iface, LINK_IFACE);
                            serde_json::json!({"type":"a(iayqs)","data":rows})
                        }
                        _ => panic!("unexpected metadata property"),
                    }
                }
                _ => panic!("unexpected query: {args:?}"),
            };
            Ok(value.to_string())
        })
    }
    fn rows() -> Value {
        serde_json::json!([[2, [192, 0, 2, 53], 0, ""]])
    }
    #[test]
    fn plaintext_link_override_preserves_explicit_os_policy() {
        for global in ["no", "yes", "opportunistic"] {
            let result = fixture(global, "no", "no", rows(), &[]).unwrap();
            assert_eq!(result[0].address, "192.0.2.53:53".parse().unwrap());
            assert_eq!(result[0].interface.index, 2);
        }
    }
    #[test]
    fn effective_encrypted_and_unknown_profiles_cannot_send_plaintext_dns() {
        for (global, link) in [
            ("yes", "yes"),
            ("no", "yes"),
            ("no", "opportunistic"),
            ("no", ""),
            ("unknown", "no"),
            ("no", "unknown"),
        ] {
            assert!(
                fixture(global, link, "no", rows(), &[]).is_err(),
                "privacy policy ignored: {global}/{link}"
            );
        }
        for dnssec in ["yes", "allow-downgrade", "unknown", ""] {
            assert!(
                fixture("no", "no", dnssec, rows(), &[]).is_err(),
                "DNSSEC policy ignored: {dnssec}"
            );
        }
    }
    #[test]
    fn loopback_and_any_assigned_local_dns_forwarder_are_rejected() {
        let local = [
            "192.0.2.53".parse().unwrap(),
            "10.241.0.1".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ];
        for address in [
            "127.0.0.1",
            "::1",
            "192.0.2.53",
            "10.241.0.1",
            "2001:db8::53",
        ] {
            let row = match address.parse::<IpAddr>().unwrap() {
                IpAddr::V4(ip) => serde_json::json!([[2, ip.octets(), 53, ""]]),
                IpAddr::V6(ip) => serde_json::json!([[10, ip.octets(), 53, ""]]),
            };
            assert!(
                fixture("no", "no", "no", row, &local).is_err(),
                "local DNS proxy accepted: {address}"
            );
        }
    }
    #[test]
    fn sni_nonstandard_port_and_unsafe_dns_are_not_downgraded() {
        for row in [
            serde_json::json!([[2, [192, 0, 2, 53], 853, ""]]),
            serde_json::json!([[2, [192, 0, 2, 53], 53, "dns.example"]]),
            serde_json::json!([[2, [0, 0, 0, 0], 53, ""]]),
            serde_json::json!([[2, [224, 0, 0, 1], 53, ""]]),
        ] {
            assert!(fixture("no", "no", "no", row, &[]).is_err());
        }
    }
    #[test]
    fn malformed_empty_or_excessive_metadata_fails_closed() {
        for row in [
            serde_json::json!([]),
            serde_json::json!([[2, [192, 0, 2], 53, ""]]),
            serde_json::json!([[10, [192, 0, 2, 53], 53, ""]]),
            serde_json::json!([[2, [192, 0, 2, 53], -1, ""]]),
            Value::Array(vec![serde_json::json!([2, [192, 0, 2, 53], 53, ""]); 17]),
        ] {
            assert!(fixture("no", "no", "no", row, &[]).is_err());
        }
    }
    #[test]
    fn ipv6_link_local_server_uses_the_physical_scope() {
        let ip: Ipv6Addr = "fe80::53".parse().unwrap();
        let result = fixture(
            "no",
            "no",
            "no",
            serde_json::json!([[10, ip.octets(), 0, ""]]),
            &[],
        )
        .unwrap();
        assert_eq!(
            result[0].address,
            SocketAddr::V6(SocketAddrV6::new(ip, 53, 0, 2))
        );
    }
}
