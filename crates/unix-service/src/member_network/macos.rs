use ipnet::IpNet;
use nelomai_client_tunnel::redundancy::{driver::RouteRefreshError, network::*};
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

pub trait MacNetworkCommands {
    fn run(&mut self, program: &str, args: &[String]) -> io::Result<String>;
    fn interface_name(&self, index: u32) -> io::Result<String>;
    fn interface_index(&self, name: &str) -> io::Result<u32>;
}

/// XNU treats an unscoped route whose destination key is zero as a primary
/// default even when its prefix is /1. Keep both unspecified host addresses
/// out of the tunnel FIB so interface-bound sockets retain the real default.
pub(crate) fn preserve_scoped_defaults(exclusions: &mut Vec<IpNet>) {
    exclusions
        .extend(nelomai_client_tunnel::redundancy::route_plan::macos_scoped_default_exclusions());
}

pub struct MacNetwork<C> {
    pub commands: C,
}

impl<C: MacNetworkCommands> NetworkSystem for MacNetwork<C> {
    fn observe_routes_on_close(&self) -> bool {
        true
    }

    fn verify_physical_endpoint(
        &mut self,
        endpoint: IpAddr,
        retained: &[RouteValue],
    ) -> io::Result<()> {
        let expected = super::session::expected_egress(endpoint, retained)?;
        let actual = physical_endpoint(&mut self.commands, endpoint)?;
        if actual.interface != expected.interface || actual.gateway != expected.gateway {
            return Err(io::Error::other("physical_route_changed"));
        }
        Ok(())
    }

    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        if matches!(key, ResourceKey::Route(_, RouteScope::WindowsInterface(_))) {
            return Err(invalid());
        }
        match key {
            ResourceKey::BoundRule { .. }
            | ResourceKey::LinkDns(_)
            | ResourceKey::LinkDnsRoute(_) => Err(invalid()),
            ResourceKey::Dns(service) => {
                valid_service(service)?;
                let text = self.commands.run(
                    "/usr/sbin/networksetup",
                    &["-getdnsservers".into(), service.clone()],
                )?;
                let mut servers = Vec::new();
                for line in text.lines().filter(|l| !l.trim().is_empty()) {
                    if line.starts_with("There aren't any DNS Servers set") {
                        continue;
                    }
                    servers.push(line.trim().parse::<IpAddr>().map_err(|_| invalid())?);
                }
                Ok(Some(NetworkValue::Dns(DnsValue {
                    service: service.clone(),
                    servers,
                })))
            }
            ResourceKey::Route(destination, scope) => {
                let family = if destination.addr().is_ipv4() {
                    "inet"
                } else {
                    "inet6"
                };
                let text = self.commands.run(
                    "/usr/sbin/netstat",
                    &["-rn".into(), "-f".into(), family.into()],
                )?;
                self.read_route_table(*destination, *scope, &text)
            }
        }
    }

    fn read_many(&mut self, keys: &[ResourceKey]) -> io::Result<Vec<Option<NetworkValue>>> {
        let mut tables = [None, None];
        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            match key {
                ResourceKey::Route(destination, scope) => {
                    if matches!(
                        scope,
                        RouteScope::LinuxMainPriority(_) | RouteScope::WindowsInterface(_)
                    ) {
                        return Err(invalid());
                    }
                    let family = usize::from(destination.addr().is_ipv6());
                    if tables[family].is_none() {
                        tables[family] = Some(self.commands.run(
                            "/usr/sbin/netstat",
                            &[
                                "-rn".into(),
                                "-f".into(),
                                if family == 0 { "inet" } else { "inet6" }.into(),
                            ],
                        )?);
                    }
                    values.push(self.read_route_table(
                        *destination,
                        *scope,
                        tables[family].as_deref().unwrap(),
                    )?);
                }
                _ => values.push(self.read(key)?),
            }
        }
        Ok(values)
    }

    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        self.compare_exchange_prepared(key, before, after, None)
            .map_err(Into::into)
    }

    fn compare_exchange_prepared(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
        prepare: Option<&mut dyn FnMut() -> io::Result<()>>,
    ) -> Result<(), RouteRefreshError> {
        let unchanged = RouteRefreshError::Unchanged;
        for value in [before, after].into_iter().flatten() {
            if value.key() != *key {
                return Err(unchanged(invalid()));
            }
            if let NetworkValue::Route(r) = value {
                if r.metric != 0
                    || r.interface == 0
                    || r.gateway.is_some()
                    || matches!(
                        r.scope,
                        RouteScope::LinuxMainPriority(_) | RouteScope::WindowsInterface(_)
                    )
                    || !utun(
                        &self
                            .commands
                            .interface_name(r.interface)
                            .map_err(unchanged)?,
                    )
                    || matches!(r.scope,RouteScope::Member(i) if i!=r.interface)
                {
                    return Err(unchanged(invalid()));
                }
            }
        }
        if before == after {
            return self.prepare_exchange(key, before, None);
        }
        match key {
            ResourceKey::BoundRule { .. }
            | ResourceKey::LinkDns(_)
            | ResourceKey::LinkDnsRoute(_) => return Err(unchanged(invalid())),
            ResourceKey::Dns(service) => {
                // An unset explicit DNS list is represented by an empty baseline,
                // not by deleting a network service.
                let Some(NetworkValue::Dns(dns)) = after else {
                    return Err(unchanged(invalid()));
                };
                valid_service(service).map_err(unchanged)?;
                let mut args = vec!["-setdnsservers".into(), service.clone()];
                if dns.servers.is_empty() {
                    args.push("Empty".into());
                } else {
                    args.extend(dns.servers.iter().map(ToString::to_string));
                }
                self.prepare_exchange(key, before, prepare)?;
                self.commands.run("/usr/sbin/networksetup", &args)?;
            }
            ResourceKey::Route(..) => {
                self.prepare_exchange(key, before, prepare)?;
                match (before, after) {
                    (Some(NetworkValue::Route(_)), Some(NetworkValue::Route(route))) => {
                        // RTM_CHANGE keeps the prefix in the kernel FIB during
                        // promotion. Only use it after the exact old row was
                        // rechecked, including after the owner intent was saved.
                        self.mutate("change", route)?;
                    }
                    (Some(NetworkValue::Route(route)), None) => self.mutate("delete", route)?,
                    (None, Some(NetworkValue::Route(route))) => {
                        self.mutate("add", route).map_err(|error| {
                            if error.kind() == io::ErrorKind::AlreadyExists {
                                unchanged(error)
                            } else {
                                error.into()
                            }
                        })?;
                    }
                    _ => return Err(unchanged(invalid())),
                }
            }
        }
        Ok(())
    }
}

impl<C: MacNetworkCommands> MacNetwork<C> {
    fn read_route_table(
        &self,
        destination: IpNet,
        scope: RouteScope,
        text: &str,
    ) -> io::Result<Option<NetworkValue>> {
        let mut result = None;
        for line in text.lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 4 {
                continue;
            }
            if table_destination(fields[0], destination.addr().is_ipv4()) != Some(destination) {
                continue;
            }
            let interface = self.commands.interface_index(fields[3])?;
            let actual_scope = if fields[2].contains('I') {
                RouteScope::Member(interface)
            } else {
                RouteScope::Global
            };
            if actual_scope != scope {
                continue;
            }
            let gateway = table_gateway(fields[1], fields[3])?;
            let value = NetworkValue::Route(RouteValue {
                destination,
                scope,
                interface,
                gateway,
                metric: 0,
            });
            if result.replace(value).is_some() {
                return Err(io::Error::other("ambiguous_owned_route"));
            }
        }
        Ok(result)
    }

    /// Read-only physical policy discovery. `owned` comes from the session's
    /// durable route journal, never from the application request.
    pub fn resolve_policy(
        &mut self,
        options: &nelomai_client_tunnel::DesktopTunnelOptions,
        endpoints: &[IpAddr],
        owned: &[RouteValue],
    ) -> io::Result<super::session::NetworkPolicy> {
        let plan =
            nelomai_client_tunnel::Ipv4RoutePlan::from_options(options).map_err(|_| invalid())?;
        if endpoints.is_empty()
            || endpoints.len() > 2
            || owned.len() > 32768
            || endpoints
                .iter()
                .any(|e| e.is_unspecified() || e.is_loopback() || e.is_multicast())
        {
            return Err(invalid());
        }
        let mut requested = plan
            .excluded_networks
            .into_iter()
            .map(IpNet::V4)
            .collect::<Vec<_>>();
        requested.extend(endpoints.iter().copied().map(IpNet::from));
        preserve_scoped_defaults(&mut requested);
        requested.sort();
        requested.dedup();
        let owned: std::collections::HashSet<_> = owned
            .iter()
            .filter(|r| r.scope == RouteScope::Global && r.gateway.is_none() && r.metric == 0)
            .map(|r| (r.destination, r.interface))
            .collect();
        let mut policy = super::session::NetworkPolicy {
            exclusions: requested.clone(),
            existing: Vec::new(),
            retained_routes: Vec::new(),
            dns_services: Vec::new(),
            metric: 0,
        };
        for ipv4 in [true, false] {
            let needed = endpoints.iter().any(|ip| ip.is_ipv4() == ipv4);
            let table = self.commands.run(
                "/usr/sbin/netstat",
                &[
                    "-rn".into(),
                    "-f".into(),
                    if ipv4 { "inet" } else { "inet6" }.into(),
                ],
            )?;
            let rows = table
                .lines()
                .map(|line| line.split_whitespace().collect::<Vec<_>>())
                .filter(|f| f.len() >= 4)
                .collect::<Vec<_>>();
            let mut os_routes = Vec::new();
            for fields in rows.iter().filter(|f| !f[2].contains('I')) {
                let Some(net) = table_destination(fields[0], ipv4) else {
                    continue;
                };
                if !owned.is_empty()
                    && utun(fields[3])
                    && matches!(table_gateway(fields[1], fields[3]), Ok(None))
                    && owned.contains(&(net, self.commands.interface_index(fields[3])?))
                {
                    continue;
                }
                policy.existing.push(net);
                os_routes.push((net, fields.as_slice()));
            }
            let mut defaults = Vec::new();
            for fields in rows
                .iter()
                .filter(|f| f[0] == "default" && physical_interface(f[3]))
            {
                let interface = self.commands.interface_index(fields[3])?;
                let gateway = table_gateway(fields[1], fields[3])?;
                if !fields[2].contains('U')
                    || fields[2].contains(['R', 'B'])
                    || gateway.is_some_and(|g| g.is_ipv4() != ipv4)
                {
                    return Err(invalid());
                }
                defaults.push(RouteValue {
                    destination: table_destination("default", ipv4).unwrap(),
                    scope: if fields[2].contains('I') {
                        RouteScope::Member(interface)
                    } else {
                        RouteScope::Global
                    },
                    interface,
                    gateway,
                    metric: 0,
                });
            }
            // Control sockets are bound to the physical interface. They can use
            // the primary OS default or an existing scoped default. Never create
            // a scoped route for them or send an unbound fallback into the VPN.
            let unscoped = defaults.iter().any(|r| r.scope == RouteScope::Global);
            let mut preferred = defaults
                .iter()
                .filter(|r| !unscoped || r.scope == RouteScope::Global);
            if let Some(default) = preferred.next().filter(|_| preferred.next().is_none()) {
                for r in defaults.iter().filter(|r| r.interface == default.interface) {
                    if r.gateway != default.gateway {
                        return Err(io::Error::other("physical_route_conflict"));
                    }
                    policy.retained_routes.push(r.clone());
                }
            } else if needed {
                return Err(io::Error::other("physical_egress_ambiguous_or_unavailable"));
            }
            for endpoint in endpoints.iter().filter(|ip| ip.is_ipv4() == ipv4) {
                let destination = IpNet::from(*endpoint);
                let mut matches: Vec<_> = os_routes
                    .iter()
                    .filter(|(net, _)| net.contains(&destination))
                    .collect();
                matches.sort_unstable_by_key(|(net, _)| std::cmp::Reverse(net.prefix_len()));
                let (best, fields) = matches
                    .first()
                    .copied()
                    .ok_or_else(|| io::Error::other("physical_egress_unavailable"))?;
                if matches
                    .get(1)
                    .is_some_and(|(net, _)| net.prefix_len() == best.prefix_len())
                {
                    return Err(io::Error::other("physical_egress_ambiguous"));
                }
                if !physical_interface(fields[3])
                    || !fields[2].contains('U')
                    || fields[2].contains(['R', 'B'])
                {
                    return Err(io::Error::other("physical_route_conflict"));
                }
                let route = RouteValue {
                    destination: table_destination(fields[0], ipv4).unwrap(),
                    scope: RouteScope::Global,
                    interface: self.commands.interface_index(fields[3])?,
                    gateway: table_gateway(fields[1], fields[3])?,
                    metric: 0,
                };
                if !policy.retained_routes.contains(&route) {
                    policy.retained_routes.push(route);
                }
            }
            if plan.exclude_local_networks {
                for fields in rows.iter().filter(|f| {
                    physical_interface(f[3]) && f[1].starts_with("link#") && !f[2].contains('I')
                }) {
                    let Some(destination) = table_destination(fields[0], ipv4) else {
                        continue;
                    };
                    if destination.prefix_len() == 0
                        || destination.prefix_len() == if ipv4 { 32 } else { 128 }
                    {
                        continue;
                    }
                    policy.exclusions.push(destination);
                    let route = RouteValue {
                        destination,
                        scope: RouteScope::Global,
                        interface: self.commands.interface_index(fields[3])?,
                        gateway: None,
                        metric: 0,
                    };
                    if !policy.retained_routes.contains(&route) {
                        policy.retained_routes.push(route);
                    }
                }
            }
        }
        policy.exclusions.sort_unstable();
        policy.exclusions.dedup();
        let services = self.commands.run(
            "/usr/sbin/networksetup",
            &["-listallnetworkservices".into()],
        )?;
        for line in services
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('*') && !s.starts_with("An asterisk"))
        {
            valid_service(line)?;
            if !policy.dns_services.iter().any(|s| s == line) {
                policy.dns_services.push(line.to_owned());
            }
        }
        if policy.dns_services.is_empty() {
            return Err(io::Error::other("physical_dns_services_unavailable"));
        }
        Ok(policy)
    }

    fn mutate(&mut self, action: &str, route: &RouteValue) -> io::Result<()> {
        let interface = self.commands.interface_name(route.interface)?;
        if route.gateway.is_some()
            || !utun(&interface)
            || self.commands.interface_index(&interface)? != route.interface
        {
            return Err(invalid());
        }
        let max_prefix = if route.destination.addr().is_ipv4() {
            32
        } else {
            128
        };
        let host = route.destination.prefix_len() == max_prefix;
        let mut args = vec![
            "-n".into(),
            action.into(),
            if max_prefix == 32 {
                "-inet".into()
            } else {
                "-inet6".into()
            },
        ];
        if host {
            args.extend(["-host".into(), route.destination.addr().to_string()]);
        } else if let IpNet::V4(net) = route.destination {
            // Darwin route(8)'s classful "-net CIDR" parser shifts low addresses:
            // 0.0.0.2/31 becomes 2.0.0.0/31. Supply the address and mask separately.
            args.extend([
                "-dst".into(),
                net.network().to_string(),
                "-netmask".into(),
                net.netmask().to_string(),
            ]);
        } else {
            args.extend(["-net".into(), route.destination.to_string()]);
        }
        args.extend(["-interface".into(), interface.clone()]);
        if matches!(route.scope, RouteScope::Member(_)) {
            args.extend(["-ifscope".into(), interface]);
        }
        self.commands.run("/sbin/route", &args)?;
        Ok(())
    }
}

pub(crate) fn physical_endpoint<C: MacNetworkCommands>(
    commands: &mut C,
    endpoint: IpAddr,
) -> io::Result<RouteValue> {
    if endpoint.is_unspecified() || endpoint.is_loopback() || endpoint.is_multicast() {
        return Err(invalid());
    }
    let text = commands.run(
        "/sbin/route",
        &[
            "-n".into(),
            "get".into(),
            if endpoint.is_ipv4() {
                "-inet"
            } else {
                "-inet6"
            }
            .into(),
            endpoint.to_string(),
        ],
    )?;
    let field = |name: &str| -> io::Result<Option<&str>> {
        let mut matches = text.lines().filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == name).then_some(value.trim())
        });
        let value = matches.next();
        if matches.next().is_some() || value == Some("") {
            return Err(invalid());
        }
        Ok(value)
    };
    let name = field("interface")?.ok_or_else(invalid)?;
    if !physical_interface(name) {
        return Err(invalid());
    }
    let flags = field("flags")?
        .ok_or_else(invalid)?
        .trim_matches(['<', '>'])
        .split(',')
        .collect::<Vec<_>>();
    if !flags.contains(&"UP") || flags.iter().any(|f| matches!(*f, "REJECT" | "BLACKHOLE")) {
        return Err(invalid());
    }
    let interface = commands.interface_index(name)?;
    let gateway = match field("gateway")? {
        None if !flags.contains(&"GATEWAY") => None,
        Some(link)
            if !flags.contains(&"GATEWAY")
                && link
                    .strip_prefix("link#")
                    .and_then(|i| i.parse::<u32>().ok())
                    == Some(interface) =>
        {
            None
        }
        Some(gateway) => {
            let address = if let Some((address, scope)) = gateway.split_once('%') {
                if scope != name {
                    return Err(invalid());
                }
                address
            } else {
                gateway
            };
            let address: IpAddr = address.parse().map_err(|_| invalid())?;
            if address.is_ipv4() != endpoint.is_ipv4()
                || address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
            {
                return Err(invalid());
            }
            Some(address)
        }
        None => return Err(invalid()),
    };
    Ok(RouteValue {
        destination: endpoint.into(),
        scope: RouteScope::Global,
        interface,
        gateway,
        metric: 0,
    })
}
pub(crate) fn table_destination(text: &str, ipv4: bool) -> Option<IpNet> {
    if text == "default" {
        return if ipv4 { "0.0.0.0/0" } else { "::/0" }.parse().ok();
    }
    if !ipv4 {
        if text.contains('%') {
            return None;
        } // link-local scoped routes aren't session data routes
        return text
            .parse::<IpNet>()
            .ok()
            .or_else(|| text.parse::<IpAddr>().ok().map(IpNet::from));
    }
    let (ip, prefix) = text
        .split_once('/')
        .map_or((text, None), |(a, p)| (a, Some(p)));
    let octets = ip
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if octets.is_empty() || octets.len() > 4 {
        return None;
    }
    let mut full = [0; 4];
    full[..octets.len()].copy_from_slice(&octets);
    let prefix = match prefix {
        Some(p) => p.parse().ok()?,
        None => octets.len() as u8 * 8,
    };
    ipnet::Ipv4Net::new(Ipv4Addr::from(full), prefix)
        .ok()
        .map(|n| IpNet::V4(n.trunc()))
}
fn table_gateway(text: &str, interface: &str) -> io::Result<Option<IpAddr>> {
    if text.starts_with("link#") || text == interface {
        return Ok(None);
    }
    let address = if let Some((address, scope)) = text.split_once('%') {
        if scope != interface {
            return Err(invalid());
        }
        address
    } else {
        text
    };
    address.parse::<IpAddr>().map(Some).map_err(|_| invalid())
}
fn utun(name: &str) -> bool {
    name.strip_prefix("utun")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
}
pub(crate) fn physical_interface(name: &str) -> bool {
    ![
        "lo", "utun", "tun", "tap", "wg", "awg", "nlm-", "ppp", "ipsec", "gif", "stf", "awdl",
        "llw", "pktap",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}
fn valid_service(service: &str) -> io::Result<()> {
    if service.is_empty() || service.len() > 256 || service.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(())
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid_native_network_state")
}

/// Real commands are reachable only when the helper constructs this adapter.
/// Unit tests use Commands instead and never execute host route/DNS commands.
#[cfg(target_os = "macos")]
pub struct NativeMacCommands;
#[cfg(target_os = "macos")]
impl MacNetworkCommands for NativeMacCommands {
    fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
        if !matches!(
            program,
            "/usr/sbin/netstat" | "/sbin/route" | "/usr/sbin/networksetup"
        ) {
            return Err(invalid());
        }
        let output = crate::process::output_with_timeout(
            std::process::Command::new(program)
                .args(args)
                .env("LANG", "C")
                .env("LC_ALL", "C"),
            crate::process::COMMAND_TIMEOUT,
        )?;
        if program == "/sbin/route"
            && args.get(1).is_some_and(|action| action == "add")
            && output
                .stderr
                .split(|byte| *byte == b'\n')
                .any(|line| line == b"route: writing to routing socket: File exists")
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if !output.status.success() {
            return Err(io::Error::other("native_network_command_failed"));
        }
        String::from_utf8(output.stdout).map_err(|_| invalid())
    }
    fn interface_name(&self, index: u32) -> io::Result<String> {
        let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
        if index == 0 || unsafe { libc::if_indextoname(index, buffer.as_mut_ptr()) }.is_null() {
            return Err(invalid());
        }
        unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
            .to_str()
            .map(str::to_string)
            .map_err(|_| invalid())
    }
    fn interface_index(&self, name: &str) -> io::Result<u32> {
        let name = std::ffi::CString::new(name).map_err(|_| invalid())?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            Err(invalid())
        } else {
            Ok(index)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Commands {
        table: String,
        calls: Vec<(String, Vec<String>)>,
        reject_route_add: bool,
    }
    impl MacNetworkCommands for Commands {
        fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
            self.calls.push((program.into(), args.to_vec()));
            if self.reject_route_add && program == "/sbin/route" && args[1] == "add" {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            Ok(self.table.clone())
        }
        fn interface_name(&self, index: u32) -> io::Result<String> {
            match index {
                10 => Ok("utun10".into()),
                20 => Ok("utun20".into()),
                _ => Err(io::ErrorKind::NotFound.into()),
            }
        }
        fn interface_index(&self, name: &str) -> io::Result<u32> {
            match name {
                "utun10" => Ok(10),
                "utun20" => Ok(20),
                _ => Err(io::ErrorKind::NotFound.into()),
            }
        }
    }
    fn route(cidr: &str, scope: RouteScope, interface: u32) -> NetworkValue {
        NetworkValue::Route(RouteValue {
            destination: cidr.parse().unwrap(),
            scope,
            interface,
            gateway: None,
            metric: 0,
        })
    }
    #[test]
    fn rejected_new_route_add_reports_no_native_write() {
        let value = route("198.18.0.1/32", RouteScope::Global, 10);
        let mut native = MacNetwork {
            commands: Commands {
                reject_route_add: true,
                ..Default::default()
            },
        };
        let result = native.compare_exchange_prepared(
            &value.key(),
            None,
            Some(&value),
            Some(&mut || Ok(())),
        );
        assert!(matches!(
            result,
            Err(RouteRefreshError::Unchanged(error)) if error.kind() == io::ErrorKind::AlreadyExists
        ));
    }

    #[test]
    fn live_replacement_rechecks_owner_after_persisting_intent() {
        use std::cell::{Cell, RefCell};

        struct RoutingCommands<'a> {
            replaced: &'a Cell<bool>,
            mutations: &'a RefCell<Vec<String>>,
        }
        impl MacNetworkCommands for RoutingCommands<'_> {
            fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                if program == "/usr/sbin/netstat" {
                    return Ok(if self.replaced.get() {
                        "198.18.0.1 link#20 UHS utun20"
                    } else {
                        "198.18.0.1 link#10 UHS utun10"
                    }
                    .into());
                }
                self.mutations.borrow_mut().push(args[1].clone());
                Ok(String::new())
            }
            fn interface_name(&self, index: u32) -> io::Result<String> {
                Commands::default().interface_name(index)
            }
            fn interface_index(&self, name: &str) -> io::Result<u32> {
                Commands::default().interface_index(name)
            }
        }

        let replaced = Cell::new(false);
        let mutations = RefCell::new(Vec::new());
        let mut native = MacNetwork {
            commands: RoutingCommands {
                replaced: &replaced,
                mutations: &mutations,
            },
        };
        let old = route("198.18.0.1/32", RouteScope::Global, 10);
        let new = route("198.18.0.1/32", RouteScope::Global, 20);
        let result = native.compare_exchange_prepared(
            &old.key(),
            Some(&old),
            Some(&new),
            Some(&mut || {
                replaced.set(true);
                Ok(())
            }),
        );
        assert!(matches!(result, Err(RouteRefreshError::Unchanged(_))));
        assert_eq!(native.read(&old.key()).unwrap(), Some(new));
        assert!(mutations.borrow().is_empty());
    }

    #[test]
    fn stop_preserves_route_reinserted_after_our_delete() {
        use nelomai_client_tunnel::redundancy::Slot;
        use std::collections::VecDeque;

        struct Store;
        impl NetworkJournalStore for Store {
            fn save(&mut self, _: &NetworkJournal) -> io::Result<()> {
                Ok(())
            }
        }

        struct RoutingCommands {
            common: Commands,
            replies: VecDeque<&'static str>,
        }
        impl MacNetworkCommands for RoutingCommands {
            fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                self.common.calls.push((program.into(), args.to_vec()));
                match self.replies.pop_front().unwrap() {
                    "route_collision" => Err(io::ErrorKind::AlreadyExists.into()),
                    value => Ok(value.into()),
                }
            }
            fn interface_name(&self, index: u32) -> io::Result<String> {
                self.common.interface_name(index)
            }
            fn interface_index(&self, name: &str) -> io::Result<u32> {
                self.common.interface_index(name)
            }
        }

        const OLD: &str = "198.18.0.1 link#10 UHS utun10";
        let old = route("198.18.0.1/32", RouteScope::Global, 10);
        let mut owner = NetworkOwner::fresh(
            MacNetwork {
                commands: RoutingCommands {
                    common: Commands::default(),
                    replies: VecDeque::from([
                        "", "", "", OLD, // Nelomai installs the initial route.
                        OLD, OLD, OLD, OLD, "",
                        OLD, // Delete ACK, then a foreign exact match.
                        OLD, OLD, // Rollback and Stop both see the foreign match.
                    ]),
                },
            },
            Store,
        );
        owner.select(Slot::A, vec![old]).unwrap();
        assert!(owner.select_with_outcome(Slot::A, vec![]).is_err());
        let stop_from = owner.system_mut().commands.common.calls.len();
        assert_eq!(
            owner.cleanup().unwrap_err().to_string(),
            "network_route_ownership_unconfirmed"
        );
        let stop_calls = &owner.system_mut().commands.common.calls[stop_from..];
        assert!(
            !stop_calls.iter().any(|(program, args)| program == "/sbin/route" && args[1] == "delete"),
            "Stop deleted the matching row installed by someone else after the original delete ACK: {stop_calls:?}"
        );
    }

    #[test]
    fn stop_preserves_foreign_route_after_a_rollback_add_is_rejected() {
        use nelomai_client_tunnel::redundancy::Slot;

        struct Store;
        impl NetworkJournalStore for Store {
            fn save(&mut self, _: &NetworkJournal) -> io::Result<()> {
                Ok(())
            }
        }

        #[derive(Default)]
        struct RoutingCommands {
            route_exists: bool,
            fail_dns: bool,
            deleted: usize,
        }
        impl MacNetworkCommands for RoutingCommands {
            fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                match (program, args[1].as_str()) {
                    ("/usr/sbin/netstat", "-f") if self.route_exists => {
                        Ok("198.18.0.1 link#10 UHS utun10".into())
                    }
                    ("/usr/sbin/netstat", "-f") => Ok(String::new()),
                    ("/sbin/route", "add") => {
                        self.route_exists = true;
                        if self.fail_dns {
                            // A competing writer wins before our rollback add.
                            Err(io::ErrorKind::AlreadyExists.into())
                        } else {
                            Ok(String::new())
                        }
                    }
                    ("/sbin/route", "delete") => {
                        assert!(self.route_exists);
                        self.route_exists = false;
                        self.deleted += 1;
                        Ok(String::new())
                    }
                    ("/usr/sbin/networksetup", _) if args[0] == "-getdnsservers" => {
                        Ok("192.0.2.53\n".into())
                    }
                    ("/usr/sbin/networksetup", _) if args[0] == "-setdnsservers" => {
                        self.fail_dns = true;
                        Err(io::Error::other("injected DNS failure"))
                    }
                    _ => panic!("unexpected command: {program} {args:?}"),
                }
            }
            fn interface_name(&self, index: u32) -> io::Result<String> {
                Commands::default().interface_name(index)
            }
            fn interface_index(&self, name: &str) -> io::Result<u32> {
                Commands::default().interface_index(name)
            }
        }

        let old = route("198.18.0.1/32", RouteScope::Global, 10);
        let mut owner = NetworkOwner::fresh(
            MacNetwork {
                commands: RoutingCommands::default(),
            },
            Store,
        );
        owner.select(Slot::A, vec![old.clone()]).unwrap();
        let dns = NetworkValue::Dns(DnsValue {
            service: "Ethernet".into(),
            servers: vec!["192.0.2.54".parse().unwrap()],
        });
        assert!(owner.select_with_outcome(Slot::A, vec![dns]).is_err());
        assert!(owner.system_mut().commands.fail_dns);
        assert_eq!(
            owner.system_mut().read(&old.key()).unwrap(),
            Some(old.clone())
        );
        owner.cleanup().unwrap();
        assert_eq!(owner.system_mut().read(&old.key()).unwrap(), Some(old));
        assert_eq!(owner.system_mut().commands.deleted, 1);
    }

    #[test]
    fn batch_reads_one_fresh_table_per_family_and_preserves_order() {
        let v4 = route("198.18.0.1/32", RouteScope::Global, 10);
        let scoped = route("198.18.0.1/32", RouteScope::Member(20), 20);
        let v6 = route("2001:db8::/32", RouteScope::Global, 10);
        let mut native = MacNetwork {
            commands: Commands {
                table: "198.18.0.1 link#10 UHS utun10\n198.18.0.1 link#20 UHSI utun20\n2001:db8::/32 link#10 USc utun10\n".into(),
                ..Default::default()
            },
        };
        let expected = vec![
            Some(scoped.clone()),
            Some(v6.clone()),
            Some(v4.clone()),
            Some(v4.clone()),
        ];
        let keys = [scoped.key(), v6.key(), v4.key(), v4.key()];
        assert_eq!(native.read_many(&keys).unwrap(), expected);
        assert_eq!(native.commands.calls.len(), 2);
        native.commands.table.clear();
        assert_eq!(native.read_many(&keys).unwrap(), vec![None; 4]);
        assert_eq!(native.commands.calls.len(), 4, "tables last only one batch");
        native
            .compare_exchange(&v4.key(), Some(&v4), None)
            .unwrap_err();
        assert_eq!(native.commands.calls.len(), 5, "CAS must query again");
    }

    #[test]
    fn batch_preserves_duplicate_and_foreign_gateway_guards() {
        let key = route("198.18.0.1/32", RouteScope::Member(20), 20).key();
        for table in [
            "198.18.0.1 link#20 UHSI utun20\n198.18.0.1 link#20 UHSI utun20\n",
            "198.18.0.1 utun10 UHSI utun20\n",
        ] {
            let mut native = MacNetwork {
                commands: Commands {
                    table: table.into(),
                    ..Default::default()
                },
            };
            assert!(native.read_many(&[key.clone(), key.clone()]).is_err());
            assert_eq!(native.commands.calls.len(), 1);
        }
    }

    #[test]
    fn named_link_gateway_preserves_exact_interface_scope_and_duplicate_guards() {
        let mut native = MacNetwork {
            commands: Commands {
                table: "198.18.0.1 utun10 UHS utun10\n198.18.0.1 utun20 UHSI utun20\n".into(),
                ..Default::default()
            },
        };
        for expected in [
            route("198.18.0.1/32", RouteScope::Global, 10),
            route("198.18.0.1/32", RouteScope::Member(20), 20),
        ] {
            assert_eq!(native.read(&expected.key()).unwrap(), Some(expected));
        }
        let absent = route("198.18.0.1/32", RouteScope::Member(10), 10);
        assert_eq!(native.read(&absent.key()).unwrap(), None);
        let scoped = route("198.18.0.1/32", RouteScope::Member(20), 20);
        native
            .commands
            .table
            .push_str("198.18.0.1 utun20 UHSI utun20\n");
        assert!(native.read(&scoped.key()).is_err());
        for gateway in ["utun10", "00:11:22:33:44:55", "fe80::1%utun10"] {
            native.commands.table = format!("198.18.0.1 {gateway} UHSI utun20\n");
            assert!(native.read(&scoped.key()).is_err(), "gateway {gateway}");
        }
    }
    #[test]
    fn probe_route_remains_scoped_to_reserve_and_never_replaces_global_dns_route() {
        let mut native = MacNetwork {
            commands: Commands {
                table: "9.9.9.9 link#10 UH utun10\n".into(),
                ..Default::default()
            },
        };
        let reserve = route("9.9.9.9/32", RouteScope::Member(20), 20);
        assert_eq!(native.read(&reserve.key()).unwrap(), None);
        native
            .compare_exchange(&reserve.key(), None, Some(&reserve))
            .unwrap();
        assert_eq!(
            native.commands.calls.last().unwrap(),
            &(
                "/sbin/route".into(),
                [
                    "-n",
                    "add",
                    "-inet",
                    "-host",
                    "9.9.9.9",
                    "-interface",
                    "utun20",
                    "-ifscope",
                    "utun20"
                ]
                .map(String::from)
                .to_vec()
            )
        );
    }
    #[test]
    fn both_ipv6_halves_are_read_and_changed_on_the_exact_owned_interface() {
        let mut native = MacNetwork {
            commands: Commands {
                table: "::/1 link#10 USc utun10\n8000::/1 link#10 USc utun10\n".into(),
                ..Default::default()
            },
        };
        for cidr in ["::/1", "8000::/1"] {
            let old = route(cidr, RouteScope::Global, 10);
            let new = route(cidr, RouteScope::Global, 20);
            assert_eq!(native.read(&old.key()).unwrap(), Some(old.clone()));
            native
                .compare_exchange(&old.key(), Some(&old), Some(&new))
                .unwrap();
            let mutations = native
                .commands
                .calls
                .iter()
                .filter(|(program, _)| program == "/sbin/route")
                .count();
            assert_eq!(mutations, if cidr == "::/1" { 1 } else { 2 });
            assert_eq!(
                native.commands.calls.last().unwrap().1,
                [
                    "-n",
                    "change",
                    "-inet6",
                    "-net",
                    cidr,
                    "-interface",
                    "utun20"
                ]
                .map(String::from)
            );
        }
    }
    #[test]
    fn ambiguous_routes_and_replaced_interface_refuse_mutation() {
        let original = route("0.0.0.0/1", RouteScope::Global, 10);
        let mut native = MacNetwork {
            commands: Commands {
                table: "0/1 link#20 USc utun20\n".into(),
                ..Default::default()
            },
        };
        assert!(native
            .compare_exchange(&original.key(), Some(&original), None)
            .is_err());
        assert!(native
            .commands
            .calls
            .iter()
            .all(|c| c.0 == "/usr/sbin/netstat"));
        native.commands.table.push_str("0/1 link#10 USc utun10\n");
        assert!(native.read(&original.key()).is_err());
    }

    struct PhysicalCommands {
        v4: &'static str,
        v6: &'static str,
    }
    impl MacNetworkCommands for PhysicalCommands {
        fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
            match (program,args.first().map(String::as_str)) {
                ("/usr/sbin/netstat",Some("-rn"))=>Ok(if args.last().map(String::as_str)==Some("inet6"){self.v6}else{self.v4}.into()),
                ("/usr/sbin/networksetup",Some("-listallnetworkservices"))=>Ok("An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Disabled Ethernet\nUSB LAN\n".into()),
                _=>panic!("discovery must be read-only: {program} {args:?}"),
            }
        }
        fn interface_name(&self, index: u32) -> io::Result<String> {
            match index {
                5 => Ok("en0".into()),
                6 => Ok("en1".into()),
                10 => Ok("utun10".into()),
                _ => Err(invalid()),
            }
        }
        fn interface_index(&self, name: &str) -> io::Result<u32> {
            match name {
                "en0" => Ok(5),
                "en1" => Ok(6),
                "utun10" => Ok(10),
                _ => Err(invalid()),
            }
        }
    }

    #[test]
    fn mac_route_get_accepts_a_direct_neighbor_and_rejects_incomplete_gateway_routes() {
        struct Lookup(&'static str);
        impl MacNetworkCommands for Lookup {
            fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
                assert_eq!(program, "/sbin/route");
                assert_eq!(args, ["-n", "get", "-inet", "192.168.64.1"]);
                Ok(self.0.into())
            }
            fn interface_name(&self, _: u32) -> io::Result<String> {
                unreachable!()
            }
            fn interface_index(&self, name: &str) -> io::Result<u32> {
                assert_eq!(name, "en0");
                Ok(5)
            }
        }
        let ip = "192.168.64.1".parse().unwrap();
        let mut native = MacNetwork {
            commands: Lookup(
                "interface: en0\nflags: <UP,HOST,DONE,LLINFO,WASCLONED,IFSCOPE,IFREF,ROUTER>\n",
            ),
        };
        let direct = RouteValue {
            destination: "192.168.64.0/24".parse().unwrap(),
            scope: RouteScope::Global,
            interface: 5,
            gateway: None,
            metric: 0,
        };
        native
            .verify_physical_endpoint(ip, std::slice::from_ref(&direct))
            .unwrap();
        for bad in [
            "interface: en0\nflags: <UP,GATEWAY>\n",
            "interface: en0\nflags: <UP>\ngateway: link#9\n",
            "interface: en0\nflags: <UP>\ngateway: \n",
        ] {
            native.commands = Lookup(bad);
            assert!(native
                .verify_physical_endpoint(ip, std::slice::from_ref(&direct))
                .is_err());
        }
    }
    #[test]
    fn physical_adapter_rejects_creation_deletion_and_replacement_on_the_uplink() {
        let mut native = MacNetwork {
            commands: PhysicalCommands { v4: "", v6: "" },
        };
        for (cidr, scope, gateway) in [
            (
                "192.0.2.1/32",
                RouteScope::Global,
                Some("192.0.2.254".parse().unwrap()),
            ),
            ("192.168.1.0/24", RouteScope::Global, None),
            (
                "0.0.0.0/0",
                RouteScope::Member(5),
                Some("192.0.2.254".parse().unwrap()),
            ),
        ] {
            let physical = NetworkValue::Route(RouteValue {
                destination: cidr.parse().unwrap(),
                scope,
                interface: 5,
                gateway,
                metric: 0,
            });
            let vpn = route(cidr, scope, 10);
            for (old, new) in [
                (None, Some(&physical)),
                (Some(&physical), None),
                (Some(&physical), Some(&vpn)),
                (Some(&vpn), Some(&physical)),
            ] {
                assert!(native.compare_exchange(&physical.key(), old, new).is_err());
            }
        }
    }

    #[test]
    fn standby_projection_ignores_only_our_tunnel_and_rejects_another_vpn_covering_the_peer() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "default 192.168.1.1 UGSc en0\n198.51.100 link#10 US utun10\n",
                v6: "",
            },
        };
        let endpoint = "198.51.100.7".parse().unwrap();
        assert!(native
            .resolve_policy(&Default::default(), &[endpoint], &[])
            .is_err());
        let NetworkValue::Route(own) = route("198.51.100.0/24", RouteScope::Global, 10) else {
            unreachable!()
        };
        let p = native
            .resolve_policy(&Default::default(), &[endpoint], &[own])
            .unwrap();
        assert_eq!(
            p.exclusions,
            [
                "0.0.0.0/32".parse().unwrap(),
                IpNet::from(endpoint),
                "::/128".parse().unwrap()
            ]
        );
        assert!(p.existing.iter().all(|n| n.prefix_len() == 0));
        assert!(p.retained_routes.iter().all(|r| r.interface == 5));
    }
    #[test]
    fn policy_discovers_physical_not_tunnel_gateway_and_preserves_existing_lan() {
        let mut native=MacNetwork {commands:PhysicalCommands {v4:"10.1.2 link#10 US utun10\ndefault 192.168.1.1 UGSc en0\n192.168.1 link#5 UCS en0\n",v6:""}};
        let policy = native
            .resolve_policy(
                &nelomai_client_tunnel::DesktopTunnelOptions {
                    exclude_local_networks: true,
                    excluded_ipv4_cidrs: vec!["203.0.113.0/24".into()],
                    policy_hash: Some("policy-1".into()),
                },
                &["198.51.100.1".parse().unwrap()],
                &[],
            )
            .unwrap();
        assert_eq!(policy.dns_services, ["Wi-Fi", "USB LAN"]);
        assert!(policy
            .retained_routes
            .iter()
            .any(|r| r.destination == "192.168.1.0/24".parse().unwrap()));
        for cidr in ["192.168.1.0/24", "198.51.100.1/32", "203.0.113.0/24"] {
            assert!(policy.exclusions.contains(&cidr.parse().unwrap()));
        }
        assert!(policy.retained_routes.iter().all(|r| r.interface == 5));
    }

    #[test]
    fn physical_endpoint_remains_read_only_even_if_an_old_journal_lists_it() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "default 192.168.1.1 UGSc en0\n198.51.100.1 192.168.1.1 UGHS en0\n",
                v6: "",
            },
        };
        let endpoint = "198.51.100.1".parse().unwrap();
        let options = nelomai_client_tunnel::DesktopTunnelOptions::default();
        let borrowed = native.resolve_policy(&options, &[endpoint], &[]).unwrap();
        assert_eq!(
            borrowed.exclusions,
            [
                "0.0.0.0/32".parse().unwrap(),
                IpNet::from(endpoint),
                "::/128".parse().unwrap()
            ]
        );
        assert_eq!(borrowed.retained_routes.len(), 2);
        let owned = native
            .resolve_policy(
                &options,
                &[endpoint],
                &[RouteValue {
                    destination: "198.51.100.1/32".parse().unwrap(),
                    scope: RouteScope::Global,
                    interface: 5,
                    gateway: Some("192.168.1.1".parse().unwrap()),
                    metric: 0,
                }],
            )
            .unwrap();
        assert_eq!(owned.exclusions, borrowed.exclusions);
        assert_eq!(owned.retained_routes, borrowed.retained_routes);
    }

    #[test]
    fn ipv6_physical_gateway_scope_is_kept_and_ambiguous_egress_is_rejected() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "",
                v6: "default fe80::1%en0 UGcg en0\n",
            },
        };
        let options = nelomai_client_tunnel::DesktopTunnelOptions::default();
        let policy = native
            .resolve_policy(&options, &["2001:db8::1".parse().unwrap()], &[])
            .unwrap();
        assert_eq!(
            policy.retained_routes[0].gateway,
            Some("fe80::1".parse().unwrap())
        );
        assert_eq!(policy.retained_routes[0].interface, 5);
        native.commands.v6 = "default fe80::1%en0 UGcIg en0\ndefault fe80::2%en1 UGcIg en1\n";
        assert!(native
            .resolve_policy(&options, &["2001:db8::1".parse().unwrap()], &[])
            .is_err());
    }

    #[test]
    fn gateway_routes_are_read_with_their_scope_and_refused_for_mutation() {
        let mut native = MacNetwork {
            commands: Commands {
                table: "2001:db8::1 fe80::1%utun10 UGHS utun10\n".into(),
                ..Default::default()
            },
        };
        let value = NetworkValue::Route(RouteValue {
            destination: "2001:db8::1/128".parse().unwrap(),
            scope: RouteScope::Global,
            interface: 10,
            gateway: Some("fe80::1".parse().unwrap()),
            metric: 0,
        });
        assert_eq!(native.read(&value.key()).unwrap(), Some(value.clone()));
        assert!(native
            .compare_exchange(&value.key(), Some(&value), None)
            .is_err());
        assert!(native
            .commands
            .calls
            .iter()
            .all(|(prog, _)| prog == "/usr/sbin/netstat"));
    }

    #[test]
    fn unused_address_family_cannot_block_a_physical_endpoint_policy() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "default 192.168.1.1 UGSc en0\n",
                v6: "default fe80::1%en0 UGcIg en0\ndefault fe80::2%en1 UGcIg en1\n",
            },
        };
        let policy = native
            .resolve_policy(
                &nelomai_client_tunnel::DesktopTunnelOptions::default(),
                &["198.51.100.1".parse().unwrap()],
                &[],
            )
            .unwrap();
        assert_eq!(policy.exclusions.len(), 3);
    }

    #[test]
    fn lan_discovery_without_ipv6_endpoint_does_not_require_choosing_ipv6_default() {
        let mut native=MacNetwork {commands:PhysicalCommands {v4:"default 192.168.1.1 UGSc en0\n",v6:"default fe80::1%en0 UGcIg en0\ndefault fe80::2%en1 UGcIg en1\nfd00:1::/64 link#5 UCS en0\nfd00:2::/64 link#6 UCS en1\n"}};
        let policy = native
            .resolve_policy(
                &nelomai_client_tunnel::DesktopTunnelOptions {
                    exclude_local_networks: true,
                    ..Default::default()
                },
                &["198.51.100.1".parse().unwrap()],
                &[],
            )
            .unwrap();
        assert_eq!(policy.exclusions.len(), 5);
        assert_eq!(policy.retained_routes.len(), 3);
        assert_eq!(policy.retained_routes[2].interface, 6);
    }
    #[test]
    fn unscoped_physical_default_is_verified_without_creating_a_scoped_default() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "default 192.168.1.1 UGSc en0\n",
                v6: "",
            },
        };
        let policy = native
            .resolve_policy(&Default::default(), &["198.51.100.1".parse().unwrap()], &[])
            .unwrap();
        assert_eq!(
            policy.exclusions,
            ["0.0.0.0/32", "198.51.100.1/32", "::/128"].map(|n| n.parse::<IpNet>().unwrap())
        );
        assert_eq!(
            policy.retained_routes,
            [RouteValue {
                destination: "0.0.0.0/0".parse().unwrap(),
                scope: RouteScope::Global,
                interface: 5,
                gateway: Some("192.168.1.1".parse().unwrap()),
                metric: 0,
            }]
        );
    }
    #[test]
    fn control_scoped_default_borrows_preexisting_matching_route() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "default 192.168.1.1 UGSc en0\ndefault 192.168.1.1 UGScI en0\n",
                v6: "",
            },
        };
        let policy = native
            .resolve_policy(&Default::default(), &["198.51.100.1".parse().unwrap()], &[])
            .unwrap();
        assert!(policy
            .retained_routes
            .iter()
            .any(|r| r.destination == "0.0.0.0/0".parse().unwrap()
                && r.scope == RouteScope::Member(5)));
        assert!(policy.exclusions.iter().all(|n| n.prefix_len() > 0));
    }
    #[test]
    fn control_scoped_default_rejects_foreign_gateway() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "default 192.168.1.1 UGSc en0\ndefault 192.168.1.2 UGScI en0\n",
                v6: "",
            },
        };
        assert!(native
            .resolve_policy(&Default::default(), &["198.51.100.1".parse().unwrap()], &[])
            .is_err());
    }

    #[test]
    fn control_scoped_defaults_include_unambiguous_physical_ipv6_without_ipv6_endpoint() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "default 192.168.1.1 UGSc en0\n",
                v6: "default fe80::1%en0 UGcIg en0\n",
            },
        };
        let p = native
            .resolve_policy(&Default::default(), &["198.51.100.1".parse().unwrap()], &[])
            .unwrap();
        assert!(p.retained_routes.contains(&RouteValue {
            destination: "::/0".parse().unwrap(),
            scope: RouteScope::Member(5),
            interface: 5,
            gateway: Some("fe80::1".parse().unwrap()),
            metric: 0
        }));
    }
    #[test]
    fn legacy_scoped_physical_default_is_read_only_on_refresh() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "default 192.168.1.1 UGSc en0\ndefault 192.168.1.1 UGScI en0\n",
                v6: "",
            },
        };
        let own = RouteValue {
            destination: "0.0.0.0/0".parse().unwrap(),
            scope: RouteScope::Member(5),
            interface: 5,
            gateway: Some("192.168.1.1".parse().unwrap()),
            metric: 0,
        };
        let p = native
            .resolve_policy(
                &Default::default(),
                &["198.51.100.1".parse().unwrap()],
                std::slice::from_ref(&own),
            )
            .unwrap();
        assert!(p.retained_routes.contains(&own));
        assert!(p.exclusions.iter().all(|n| n.prefix_len() > 0));
    }
    #[test]
    fn control_scoped_default_never_claims_ownership_of_global_os_default() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "default 192.168.1.1 UGSc en0\ndefault 192.168.1.1 UGScI en0\n",
                v6: "",
            },
        };
        let own = RouteValue {
            destination: "0.0.0.0/0".parse().unwrap(),
            scope: RouteScope::Member(5),
            interface: 5,
            gateway: Some("192.168.1.1".parse().unwrap()),
            metric: 0,
        };
        let options = nelomai_client_tunnel::DesktopTunnelOptions {
            excluded_ipv4_cidrs: vec!["0.0.0.0/0".into()],
            policy_hash: Some("explicit-user-exclusion".into()),
            ..Default::default()
        };
        let p = native
            .resolve_policy(&options, &["198.51.100.1".parse().unwrap()], &[own])
            .unwrap();
        assert!(p.retained_routes.iter().any(
            |r| r.destination == "0.0.0.0/0".parse().unwrap() && r.scope == RouteScope::Global
        ));
        assert!(p.exclusions.contains(&"0.0.0.0/0".parse().unwrap()));
    }
}
