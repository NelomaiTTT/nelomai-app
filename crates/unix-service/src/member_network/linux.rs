//! Private pair route adapter. Not constructed by the service until Linux pair
//! lifecycle, resolver and reverse-path-filter ownership are connected.

use ipnet::IpNet;
use nelomai_client_tunnel::redundancy::network::*;
use serde_json::{Map, Value};
use std::{io, net::IpAddr};

mod dns;
mod physical;
pub use physical::PhysicalRoutes;

pub trait LinuxNetworkCommands {
    fn ip(&mut self, args: &[String]) -> io::Result<String>;
    fn busctl(&mut self, _args: &[String]) -> io::Result<String> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn interface_name(&self, index: u32) -> io::Result<String>;
    fn interface_index(&self, name: &str) -> io::Result<u32>;
}

/// Assigned by the privileged owner, never accepted from application IPC.
/// The enclosing session must persist these bindings with its native identity.
#[derive(Clone)]
pub struct MemberTable {
    pub interface: u32,
    pub name: String,
    pub table: u32,
    pub priority: u32,
}

pub struct LinuxNetwork<C> {
    pub commands: C,
    members: Vec<MemberTable>,
}

impl<C: LinuxNetworkCommands> LinuxNetwork<C> {
    /// Read-only preflight before any member launch or route mutation.
    pub fn resolve_policy(
        &mut self,
        options: &nelomai_client_tunnel::DesktopTunnelOptions,
        endpoints: &[IpAddr],
        owned: &[IpNet],
    ) -> io::Result<super::session::NetworkPolicy> {
        self.verify_resolver()?;
        let physical = self.resolve_physical_routes(options, endpoints, owned)?;
        Ok(super::session::NetworkPolicy {
            bypasses: physical.bypasses,
            retained_routes: physical.retained_routes,
            dns_services: Vec::new(),
            metric: 42,
        })
    }
    pub fn new(commands: C, members: impl IntoIterator<Item = MemberTable>) -> io::Result<Self> {
        let mut result = Self {
            commands,
            members: Vec::new(),
        };
        for member in members {
            result.register_member(member)?;
        }
        Ok(result)
    }
    /// Register only after the privileged factory has persisted a freshly
    /// captured member identity and free table/priority assignment. No network
    /// commands here; empty/primary-only construction never waits for standby.
    /// Replacing a live binding is deliberately not an adoption/recovery path.
    pub fn register_member(&mut self, member: MemberTable) -> io::Result<()> {
        if self.members.len() >= 2
            || member.interface == 0
            || !valid_name(&member.name)
            || member.table <= 255
            || !(1..32766).contains(&member.priority)
            || self.members.iter().any(|m| {
                m.interface == member.interface
                    || m.name == member.name
                    || m.table == member.table
                    || m.priority == member.priority
            })
        {
            return Err(invalid());
        }
        self.members.push(member);
        Ok(())
    }
    pub fn member_rule(&self, interface: u32, ipv6: bool) -> io::Result<NetworkValue> {
        let m = self.member(interface)?;
        Ok(NetworkValue::BoundRule(BoundRuleValue {
            ipv6,
            priority: m.priority,
            table: m.table,
            interface,
        }))
    }
    fn member(&self, interface: u32) -> io::Result<&MemberTable> {
        self.members
            .iter()
            .find(|m| m.interface == interface)
            .ok_or_else(invalid)
    }
    fn table(&self, scope: RouteScope) -> io::Result<u32> {
        match scope {
            RouteScope::Global => Ok(254),
            RouteScope::Member(i) => Ok(self.member(i)?.table),
        }
    }
    fn name(&self, interface: u32) -> io::Result<String> {
        let name = self.commands.interface_name(interface)?;
        if !valid_name(&name) || self.commands.interface_index(&name)? != interface {
            return Err(invalid());
        }
        if self
            .members
            .iter()
            .any(|m| m.interface == interface && m.name != name)
        {
            return Err(invalid());
        }
        Ok(name)
    }
    fn rule_name(&self, interface: u32) -> io::Result<(&str, bool)> {
        let m = self.member(interface)?;
        match self.commands.interface_index(&m.name) {
            Ok(index) if index == interface => Ok((&m.name, false)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((&m.name, true)),
            _ => Err(invalid()),
        }
    }
    fn read_route(
        &mut self,
        destination: IpNet,
        scope: RouteScope,
    ) -> io::Result<Option<NetworkValue>> {
        self.read_route_mode(destination, scope, false)
    }
    fn read_route_mode(
        &mut self,
        destination: IpNet,
        scope: RouteScope,
        retained: bool,
    ) -> io::Result<Option<NetworkValue>> {
        let table = self.table(scope)?;
        let text = self.commands.ip(&[
            "-j".into(),
            "-N".into(),
            family(destination.addr().is_ipv6()).into(),
            "route".into(),
            "show".into(),
            "table".into(),
            "all".into(),
            "exact".into(),
            destination.to_string(),
        ])?;
        let rows = rows(&text)?;
        let mut result = None;
        for row in rows {
            let row = row.as_object().ok_or_else(invalid)?;
            // A table-specific dump can fail when the table has never existed.
            // Dump all tables and filter, rather than treating command failures
            // as an empty routing table. Main table may be omitted by iproute2.
            let actual_table = if row.contains_key("table") {
                number(row, "table")?
            } else {
                254
            };
            if actual_table != table {
                continue;
            }
            // Query was already exact. Unexpected destinations are not absence.
            let dst = string(row, "dst")?;
            let actual = if dst == "default" {
                if destination.addr().is_ipv4() {
                    "0.0.0.0/0"
                } else {
                    "::/0"
                }
                .parse()
                .map_err(|_| invalid())?
            } else {
                dst.parse::<IpNet>()
                    .or_else(|_| dst.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|_| invalid())?
            };
            if actual != destination {
                return Err(invalid());
            }
            let mut accepted = vec![
                "dst", "dev", "gateway", "protocol", "scope", "metric", "flags", "type", "table",
                "pref",
            ];
            if retained {
                accepted.extend(["prefsrc", "expires"]);
                physical::validate_metadata(row, destination)?;
            }
            only_keys(row, &accepted)?;
            if (!retained && number(row, "protocol")? != 4)
                || row.get("type").is_some_and(|v| v != "unicast")
                || row
                    .get("flags")
                    .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
                || row.get("pref").is_some_and(|v| v != "medium")
                || (row.contains_key("table") && number(row, "table")? != table)
            {
                return Err(invalid());
            }
            let name = string(row, "dev")?;
            let interface = self.commands.interface_index(name)?;
            if self.name(interface)? != name
                || matches!(scope,RouteScope::Member(i) if i != interface)
            {
                return Err(invalid());
            }
            let gateway = row
                .get("gateway")
                .map(|v| {
                    v.as_str()
                        .ok_or_else(invalid)?
                        .parse::<IpAddr>()
                        .map_err(|_| invalid())
                })
                .transpose()?;
            if gateway.is_some_and(|g| g.is_ipv4() != destination.addr().is_ipv4()) {
                return Err(invalid());
            }
            if let Some(native_scope) = row.get("scope") {
                let expected = if gateway.is_none() { "link" } else { "global" };
                let expected_numeric = if gateway.is_none() { 253 } else { 0 };
                if native_scope != expected && number(row, "scope")? != expected_numeric {
                    return Err(invalid());
                }
            }
            let metric = row
                .get("metric")
                .map(|_| number(row, "metric"))
                .transpose()?
                .unwrap_or(0);
            if result
                .replace(NetworkValue::Route(RouteValue {
                    destination,
                    scope,
                    interface,
                    gateway,
                    metric,
                }))
                .is_some()
            {
                return Err(invalid());
            }
        }
        Ok(result)
    }
    fn read_rule(&mut self, ipv6: bool, priority: u32) -> io::Result<Option<NetworkValue>> {
        let member = self
            .members
            .iter()
            .find(|m| m.priority == priority)
            .ok_or_else(invalid)?
            .clone();
        let text = self.commands.ip(&[
            "-j".into(),
            "-N".into(),
            family(ipv6).into(),
            "rule".into(),
            "show".into(),
        ])?;
        let mut result = None;
        for row in rows(&text)? {
            let row = row.as_object().ok_or_else(invalid)?;
            if number(row, "priority")? != priority {
                continue;
            }
            only_keys(
                row,
                &[
                    "priority",
                    "src",
                    "table",
                    "protocol",
                    "oif",
                    "oif_detached",
                ],
            )?;
            let (name, absent) = self.rule_name(member.interface)?;
            if string(row, "src")? != "all"
                || number(row, "table")? != member.table
                || number(row, "protocol")? != 4
                || string(row, "oif")? != name
                || row.contains_key("oif_detached") != absent
                || row.get("oif_detached").is_some_and(|v| !v.is_null())
            {
                return Err(invalid());
            }
            if result
                .replace(self.member_rule(member.interface, ipv6)?)
                .is_some()
            {
                return Err(invalid());
            }
        }
        Ok(result)
    }
    fn validate(&self, value: &NetworkValue) -> io::Result<()> {
        match value {
            NetworkValue::Route(r) => {
                if r.interface == 0
                    || r.destination != r.destination.trunc()
                    || r.gateway
                        .is_some_and(|g| g.is_ipv4() != r.destination.addr().is_ipv4())
                    || matches!(r.scope,RouteScope::Member(i) if i!=r.interface)
                {
                    return Err(invalid());
                }
                self.table(r.scope)?;
            }
            NetworkValue::BoundRule(r) if self.member_rule(r.interface, r.ipv6)? == *value => {}
            _ => return Err(invalid()),
        }
        Ok(())
    }
    fn mutate(&mut self, add: bool, value: &NetworkValue) -> io::Result<()> {
        let action = if add { "add" } else { "del" };
        let args = match value {
            NetworkValue::Route(r) => {
                let mut args = vec![
                    family(r.destination.addr().is_ipv6()).into(),
                    "route".into(),
                    action.into(),
                    r.destination.to_string(),
                    "table".into(),
                    self.table(r.scope)?.to_string(),
                    "dev".into(),
                    self.name(r.interface)?,
                    "metric".into(),
                    r.metric.to_string(),
                    "proto".into(),
                    "4".into(),
                ];
                if let Some(gateway) = r.gateway {
                    args.extend(["via".into(), gateway.to_string()]);
                } else if r.destination.addr().is_ipv4() {
                    args.extend(["scope".into(), "link".into()]);
                }
                args
            }
            NetworkValue::BoundRule(r) => vec![
                family(r.ipv6).into(),
                "rule".into(),
                action.into(),
                "priority".into(),
                r.priority.to_string(),
                "oif".into(),
                self.rule_name(r.interface)?.0.into(),
                "lookup".into(),
                r.table.to_string(),
                "protocol".into(),
                "4".into(),
            ],
            _ => return Err(invalid()),
        };
        self.commands.ip(&args)?;
        Ok(())
    }
}

impl<C: LinuxNetworkCommands> NetworkSystem for LinuxNetwork<C> {
    fn dns_resources(
        &self,
        interface: u32,
        servers: &[IpAddr],
        services: &[String],
    ) -> io::Result<Vec<NetworkValue>> {
        self.member(interface)?;
        if !services.is_empty() {
            return Err(invalid());
        }
        if servers.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![
            NetworkValue::LinkDns(LinkDnsValue {
                interface,
                servers: servers.to_vec(),
            }),
            NetworkValue::LinkDnsRoute(interface),
        ])
    }
    fn verify_retained_route(&mut self, route: &RouteValue) -> io::Result<bool> {
        if route.scope != RouteScope::Global {
            return Err(invalid());
        }
        Ok(self.read_route_mode(route.destination, route.scope, true)?
            == Some(NetworkValue::Route(route.clone())))
    }
    fn route_resources(&self, route: RouteValue) -> io::Result<Vec<NetworkValue>> {
        let mut values = vec![NetworkValue::Route(route.clone())];
        self.validate(&values[0])?;
        if let RouteScope::Member(interface) = route.scope {
            values.push(self.member_rule(interface, route.destination.addr().is_ipv6())?);
        }
        Ok(values)
    }
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        match key {
            ResourceKey::Route(destination, scope) => self.read_route(*destination, *scope),
            ResourceKey::BoundRule { ipv6, priority } => self.read_rule(*ipv6, *priority),
            ResourceKey::LinkDns(_) | ResourceKey::LinkDnsRoute(_) => self.read_link_dns(key),
            ResourceKey::Dns(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pair_dns_not_connected",
            )),
        }
    }
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        if matches!(key, ResourceKey::LinkDns(_) | ResourceKey::LinkDnsRoute(_)) {
            return self.compare_link_dns(key, before, after);
        }
        for value in [before, after].into_iter().flatten() {
            if value.key() != *key {
                return Err(invalid());
            }
            self.validate(value)?;
        }
        if let Some(value) = after {
            match value {
                NetworkValue::Route(r) => {
                    self.name(r.interface)?;
                }
                NetworkValue::BoundRule(r) => {
                    self.name(r.interface)?;
                }
                _ => return Err(invalid()),
            }
        }
        if self.read(key)?.as_ref() != before {
            return Err(io::Error::other("network_resource_changed"));
        }
        if before == after {
            return Ok(());
        }
        if let Some(value) = before {
            self.mutate(false, value)?;
        }
        if let Some(value) = after {
            self.mutate(true, value)?;
        }
        Ok(())
    }
}
fn family(ipv6: bool) -> &'static str {
    if ipv6 {
        "-6"
    } else {
        "-4"
    }
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid_linux_pair_network_state",
    )
}
fn rows(text: &str) -> io::Result<Vec<Value>> {
    if text.len() > 8 * 1024 * 1024 {
        return Err(invalid());
    }
    let rows: Vec<Value> = serde_json::from_str(text).map_err(|_| invalid())?;
    if rows.len() > 32768 {
        return Err(invalid());
    }
    Ok(rows)
}
fn string<'a>(row: &'a Map<String, Value>, key: &str) -> io::Result<&'a str> {
    row.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn number(row: &Map<String, Value>, key: &str) -> io::Result<u32> {
    let value = row.get(key).ok_or_else(invalid)?;
    if let Some(n) = value.as_u64() {
        return u32::try_from(n).map_err(|_| invalid());
    }
    let text = value.as_str().ok_or_else(invalid)?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    text.parse().map_err(|_| invalid())
}
fn only_keys(row: &Map<String, Value>, keys: &[&str]) -> io::Result<()> {
    if row.keys().any(|k| !keys.contains(&k.as_str())) {
        Err(invalid())
    } else {
        Ok(())
    }
}

/// Uses the same allowlisted executable discovery and bounded subprocess seam
/// as the existing Linux route manager. Unit tests never construct this type.
#[cfg(target_os = "linux")]
pub struct NativeLinuxCommands {
    ip: std::path::PathBuf,
}
#[cfg(target_os = "linux")]
impl NativeLinuxCommands {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            ip: crate::routes::ip_command()
                .map_err(|_| io::Error::other("ip_command_unavailable"))?,
        })
    }
}
#[cfg(target_os = "linux")]
impl LinuxNetworkCommands for NativeLinuxCommands {
    fn busctl(&mut self, args: &[String]) -> io::Result<String> {
        use std::os::unix::fs::MetadataExt;
        let program = ["/usr/bin/busctl", "/bin/busctl"]
            .into_iter()
            .find(|path| {
                std::fs::metadata(path).is_ok_and(|m| {
                    m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.mode() & 0o111 != 0
                })
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "busctl_unavailable"))?;
        let output = crate::process::output_with_timeout(
            std::process::Command::new(program)
                .args([
                    "--system",
                    "--no-pager",
                    "--json=short",
                    "--timeout=5",
                    "--allow-interactive-authorization=no",
                ])
                .args(args)
                .env("LANG", "C")
                .env("LC_ALL", "C"),
            crate::process::COMMAND_TIMEOUT,
        )?;
        if !output.status.success() {
            return Err(io::Error::other("linux_pair_resolver_command_failed"));
        }
        String::from_utf8(output.stdout).map_err(|_| invalid())
    }
    fn ip(&mut self, args: &[String]) -> io::Result<String> {
        let output = crate::process::output_with_timeout(
            std::process::Command::new(&self.ip)
                .args(args)
                .env("LANG", "C")
                .env("LC_ALL", "C"),
            crate::process::COMMAND_TIMEOUT,
        )?;
        if !output.status.success() {
            return Err(io::Error::other("linux_pair_network_command_failed"));
        }
        String::from_utf8(output.stdout).map_err(|_| invalid())
    }
    fn interface_name(&self, index: u32) -> io::Result<String> {
        if index == 0 {
            return Err(invalid());
        }
        let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
        if unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) }.is_null() {
            let error = io::Error::last_os_error();
            return Err(
                if matches!(error.raw_os_error(), Some(libc::ENXIO | libc::ENODEV)) {
                    io::ErrorKind::NotFound.into()
                } else {
                    error
                },
            );
        }
        unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
            .to_str()
            .map(str::to_string)
            .map_err(|_| invalid())
    }
    fn interface_index(&self, name: &str) -> io::Result<u32> {
        if !valid_name(name) {
            return Err(invalid());
        }
        let name = std::ffi::CString::new(name).map_err(|_| invalid())?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            let error = io::Error::last_os_error();
            return Err(
                if matches!(error.raw_os_error(), Some(libc::ENXIO | libc::ENODEV)) {
                    io::ErrorKind::NotFound.into()
                } else {
                    error
                },
            );
        }
        Ok(index)
    }
}

#[cfg(test)]
mod tests;
