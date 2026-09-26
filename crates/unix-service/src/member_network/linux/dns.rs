//! Per-owned-link resolved properties. No RevertLink: each independently
//! mutable property belongs in NetworkOwner's write-ahead/rollback transaction.
//! busctl get-property JSON is {type: signature, data: property-value}; unlike
//! method replies, property data is not wrapped in an extra message array.
use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

const SERVICE: &str = "org.freedesktop.resolve1";
const MANAGER: &str = "/org/freedesktop/resolve1";
const MANAGER_IFACE: &str = "org.freedesktop.resolve1.Manager";
const LINK_IFACE: &str = "org.freedesktop.resolve1.Link";

impl<C: LinuxNetworkCommands> LinuxNetwork<C> {
    // Absence is accepted only when BOTH the captured name and index are gone.
    // Factory must additionally validate its durable native member identity.
    fn dns_link_present(&self, interface: u32) -> io::Result<bool> {
        let m = self.member(interface)?;
        if interface > i32::MAX as u32 {
            return Err(invalid());
        }
        match (
            self.commands.interface_name(interface),
            self.commands.interface_index(&m.name),
        ) {
            (Ok(name), Ok(index)) if name == m.name && index == interface => Ok(true),
            (Err(a), Err(b))
                if a.kind() == io::ErrorKind::NotFound && b.kind() == io::ErrorKind::NotFound =>
            {
                Ok(false)
            }
            _ => Err(invalid()),
        }
    }
    fn property(
        &mut self,
        path: &str,
        iface: &str,
        name: &str,
        signature: &str,
    ) -> io::Result<Value> {
        let text = self.commands.busctl(&[
            "get-property".into(),
            SERVICE.into(),
            path.into(),
            iface.into(),
            name.into(),
        ])?;
        if text.len() > 64 * 1024 {
            return Err(invalid());
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Property {
            #[serde(rename = "type")]
            signature: String,
            data: Value,
        }
        let value: Property = serde_json::from_str(&text).map_err(|_| invalid())?;
        if value.signature != signature {
            return Err(invalid());
        }
        Ok(value.data)
    }
    pub(super) fn verify_resolver(&mut self) -> io::Result<()> {
        let mode = self.property(MANAGER, MANAGER_IFACE, "ResolvConfMode", "s")?;
        if mode != "stub" && mode != "static" {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pair_dns_stub_required",
            ));
        }
        if self.property(MANAGER, MANAGER_IFACE, "DNSStubListener", "s")? != "yes" {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pair_dns_stub_required",
            ));
        }
        Ok(())
    }
    pub(super) fn read_link_dns(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        let interface = link_index(key)?;
        if !self.dns_link_present(interface)? {
            return Ok(None);
        }
        // systemd's sd_bus_path_encode escapes the initial ASCII digit, not
        // merely a leading underscore: ifindex 10 is link/_310, not link/_10.
        let decimal = interface.to_string();
        let path = format!(
            "{MANAGER}/link/_{:02x}{}",
            decimal.as_bytes()[0],
            &decimal[1..]
        );
        let result = match key {
            ResourceKey::LinkDns(_) => {
                // DNS alone hides port/SNI. Never mistake a foreign DNSEx value
                // for our plain address and then erase the extra configuration.
                let data = self.property(&path, LINK_IFACE, "DNSEx", "a(iayqs)")?;
                let rows = data.as_array().ok_or_else(invalid)?;
                if rows.len() > 16 {
                    return Err(invalid());
                }
                let mut servers = Vec::new();
                for row in rows {
                    let row = row.as_array().ok_or_else(invalid)?;
                    if row.len() != 4 || row[2].as_u64() != Some(0) || row[3] != "" {
                        return Err(invalid());
                    }
                    let bytes = row[1]
                        .as_array()
                        .ok_or_else(invalid)?
                        .iter()
                        .map(|n| {
                            n.as_u64()
                                .and_then(|n| u8::try_from(n).ok())
                                .ok_or_else(invalid)
                        })
                        .collect::<io::Result<Vec<_>>>()?;
                    let ip = match row[0].as_i64() {
                        Some(2) => IpAddr::V4(Ipv4Addr::from(
                            <[u8; 4]>::try_from(bytes).map_err(|_| invalid())?,
                        )),
                        Some(10) => IpAddr::V6(Ipv6Addr::from(
                            <[u8; 16]>::try_from(bytes).map_err(|_| invalid())?,
                        )),
                        _ => return Err(invalid()),
                    };
                    if ip.is_unspecified() || ip.is_multicast() || servers.contains(&ip) {
                        return Err(invalid());
                    }
                    servers.push(ip);
                }
                if servers.is_empty() {
                    None
                } else {
                    Some(NetworkValue::LinkDns(LinkDnsValue { interface, servers }))
                }
            }
            ResourceKey::LinkDnsRoute(_) => {
                let data = self.property(&path, LINK_IFACE, "Domains", "a(sb)")?;
                if data == serde_json::json!([]) {
                    None
                } else if data == serde_json::json!([[".", true]]) {
                    Some(NetworkValue::LinkDnsRoute(interface))
                } else {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        };
        if !self.dns_link_present(interface)? {
            return Err(io::Error::other("network_resource_changed"));
        }
        Ok(result)
    }
    pub(super) fn compare_link_dns(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        let interface = link_index(key)?;
        for value in [before, after].into_iter().flatten() {
            if value.key() != *key {
                return Err(invalid());
            }
            if let NetworkValue::LinkDns(d) = value {
                if d.servers.is_empty()
                    || d.servers.len() > 16
                    || d.servers
                        .iter()
                        .any(|s| s.is_unspecified() || s.is_multicast())
                    || d.servers
                        .iter()
                        .collect::<std::collections::HashSet<_>>()
                        .len()
                        != d.servers.len()
                {
                    return Err(invalid());
                }
            }
        }
        if self.read_link_dns(key)?.as_ref() != before {
            return Err(io::Error::other("network_resource_changed"));
        }
        if before == after {
            return Ok(());
        }
        if after.is_some() {
            self.verify_resolver()?;
            // The two manager queries may block. Do not apply a stale CAS
            // observation after another owner changed this link meanwhile.
            if self.read_link_dns(key)?.as_ref() != before {
                return Err(io::Error::other("network_resource_changed"));
            }
        }
        if !self.dns_link_present(interface)? {
            return Err(invalid());
        }
        let mut args = vec![
            "call".into(),
            SERVICE.into(),
            MANAGER.into(),
            MANAGER_IFACE.into(),
        ];
        match key {
            ResourceKey::LinkDns(_) => {
                let servers = match after {
                    Some(NetworkValue::LinkDns(d)) => d.servers.as_slice(),
                    None => &[],
                    _ => return Err(invalid()),
                };
                args.extend([
                    "SetLinkDNS".into(),
                    "ia(iay)".into(),
                    interface.to_string(),
                    servers.len().to_string(),
                ]);
                for ip in servers {
                    let (family, bytes) = match ip {
                        IpAddr::V4(ip) => (2, ip.octets().to_vec()),
                        IpAddr::V6(ip) => (10, ip.octets().to_vec()),
                    };
                    args.extend([family.to_string(), bytes.len().to_string()]);
                    args.extend(bytes.iter().map(ToString::to_string));
                }
            }
            ResourceKey::LinkDnsRoute(_) => {
                args.extend([
                    "SetLinkDomains".into(),
                    "ia(sb)".into(),
                    interface.to_string(),
                ]);
                if after.is_some() {
                    args.extend(["1".into(), ".".into(), "true".into()]);
                } else {
                    args.push("0".into());
                }
            }
            _ => return Err(invalid()),
        }
        // One setter instead of a delete/add pair. NetworkOwner verifies readback
        // and rolls back known results; an unrecognized partial value stays
        // cleanup-pending rather than authorizing a blind resolver reset.
        self.commands.busctl(&args)?;
        if !self.dns_link_present(interface)? {
            return Err(invalid());
        }
        Ok(())
    }
}

fn link_index(key: &ResourceKey) -> io::Result<u32> {
    match key {
        ResourceKey::LinkDns(i) | ResourceKey::LinkDnsRoute(i)
            if *i > 0 && *i <= i32::MAX as u32 =>
        {
            Ok(*i)
        }
        _ => Err(invalid()),
    }
}
