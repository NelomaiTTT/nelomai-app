use ipnet::IpNet;
use nelomai_client_tunnel::redundancy::network::*;
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

pub trait MacNetworkCommands {
    fn run(&mut self, program: &str, args: &[String]) -> io::Result<String>;
    fn interface_name(&self, index: u32) -> io::Result<String>;
    fn interface_index(&self, name: &str) -> io::Result<u32>;
}

pub struct MacNetwork<C> {
    pub commands: C,
}

impl<C: MacNetworkCommands> NetworkSystem for MacNetwork<C> {
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        match key {
            ResourceKey::BoundRule { .. } => Err(invalid()),
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
                let mut result = None;
                for line in text.lines() {
                    let fields = line.split_whitespace().collect::<Vec<_>>();
                    if fields.len() < 4 {
                        continue;
                    }
                    if table_destination(fields[0], destination.addr().is_ipv4())
                        != Some(*destination)
                    {
                        continue;
                    }
                    let interface = self.commands.interface_index(fields[3])?;
                    let actual_scope = if fields[2].contains('I') {
                        RouteScope::Member(interface)
                    } else {
                        RouteScope::Global
                    };
                    if actual_scope != *scope {
                        continue;
                    }
                    let gateway = table_gateway(fields[1], fields[3])?;
                    let value = NetworkValue::Route(RouteValue {
                        destination: *destination,
                        scope: *scope,
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
        }
    }

    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        for value in [before, after].into_iter().flatten() {
            if value.key() != *key {
                return Err(invalid());
            }
            if let NetworkValue::Route(r) = value {
                if r.metric != 0
                    || r.interface == 0
                    || matches!(r.scope,RouteScope::Member(i) if i!=r.interface)
                {
                    return Err(invalid());
                }
            }
        }
        if self.read(key)?.as_ref() != before {
            return Err(io::Error::other("network_resource_changed"));
        }
        if before == after {
            return Ok(());
        }
        match key {
            ResourceKey::BoundRule { .. } => return Err(invalid()),
            ResourceKey::Dns(service) => {
                // An unset explicit DNS list is represented by an empty baseline,
                // not by deleting a network service.
                let Some(NetworkValue::Dns(dns)) = after else {
                    return Err(invalid());
                };
                valid_service(service)?;
                let mut args = vec!["-setdnsservers".into(), service.clone()];
                if dns.servers.is_empty() {
                    args.push("Empty".into());
                } else {
                    args.extend(dns.servers.iter().map(ToString::to_string));
                }
                self.commands.run("/usr/sbin/networksetup", &args)?;
            }
            ResourceKey::Route(..) => {
                if let Some(NetworkValue::Route(route)) = before {
                    self.mutate("delete", route)?;
                }
                if let Some(NetworkValue::Route(route)) = after {
                    self.mutate("add", route)?;
                }
            }
        }
        Ok(())
    }
}

impl<C: MacNetworkCommands> MacNetwork<C> {
    /// Read-only physical policy discovery. `owned` comes from the session's
    /// durable route journal, never from the application request.
    pub fn resolve_policy(
        &mut self,
        options: &nelomai_client_tunnel::DesktopTunnelOptions,
        endpoints: &[IpAddr],
        owned: &[IpNet],
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
        requested.sort();
        requested.dedup();
        let mut policy = super::session::NetworkPolicy {
            bypasses: Vec::new(),
            retained_routes: Vec::new(),
            dns_services: Vec::new(),
            metric: 0,
        };
        for ipv4 in [true, false] {
            let needed = requested.iter().any(|n| n.addr().is_ipv4() == ipv4);
            if !needed && !plan.exclude_local_networks {
                continue;
            }
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
            if !needed {
                // No endpoint or policy bypass needs a gateway in this family.
                // Existing connected LAN routes can still be retained verbatim
                // on several physical adapters without selecting a default.
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
                    policy.retained_routes.push(RouteValue {
                        destination,
                        scope: RouteScope::Global,
                        interface: self.commands.interface_index(fields[3])?,
                        gateway: None,
                        metric: 0,
                    });
                }
                continue;
            }
            let mut defaults = Vec::new();
            for fields in rows
                .iter()
                .filter(|f| f[0] == "default" && physical_interface(f[3]))
            {
                let index = self.commands.interface_index(fields[3])?;
                let gateway = table_gateway(fields[1], fields[3])?.ok_or_else(invalid)?;
                if gateway.is_ipv4() != ipv4 {
                    return Err(invalid());
                }
                defaults.push((fields[2].contains('I'), index, gateway));
            }
            // Prefer the OS's unscoped physical default; never pick an arbitrary
            // adapter when several equally scoped defaults are present.
            if defaults.iter().any(|r| !r.0) {
                defaults.retain(|r| !r.0);
            }
            defaults.sort();
            defaults.dedup();
            if defaults.len() != 1 {
                return Err(io::Error::other("physical_egress_ambiguous_or_unavailable"));
            }
            let (_, interface, gateway) = defaults[0];
            let name = self.commands.interface_name(interface)?;
            for destination in requested
                .iter()
                .copied()
                .filter(|n| n.addr().is_ipv4() == ipv4)
            {
                let route = RouteValue {
                    destination,
                    scope: RouteScope::Global,
                    interface,
                    gateway: Some(gateway),
                    metric: 0,
                };
                if owned.contains(&destination) {
                    policy.bypasses.push(route);
                    continue;
                }
                let matches = rows
                    .iter()
                    .filter(|f| {
                        !f[2].contains('I') && table_destination(f[0], ipv4) == Some(destination)
                    })
                    .collect::<Vec<_>>();
                match matches.as_slice() {
                    [] => policy.bypasses.push(route),
                    [fields] if fields[3] == name => {
                        let existing_gateway = table_gateway(fields[1], fields[3])?;
                        if existing_gateway.is_some_and(|g| g != gateway) {
                            return Err(io::Error::other("physical_route_conflict"));
                        }
                        policy.retained_routes.push(RouteValue {
                            gateway: existing_gateway,
                            ..route
                        });
                    }
                    _ => return Err(io::Error::other("physical_route_conflict")),
                }
            }
            if plan.exclude_local_networks {
                for fields in rows
                    .iter()
                    .filter(|f| f[3] == name && f[1].starts_with("link#") && !f[2].contains('I'))
                {
                    let Some(destination) = table_destination(fields[0], ipv4) else {
                        continue;
                    };
                    let bits = if ipv4 { 32 } else { 128 };
                    if destination.prefix_len() == 0
                        || destination.prefix_len() == bits
                        || requested.contains(&destination)
                    {
                        continue;
                    }
                    policy.retained_routes.push(RouteValue {
                        destination,
                        scope: RouteScope::Global,
                        interface,
                        gateway: None,
                        metric: 0,
                    });
                }
            }
        }
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
            if host { "-host".into() } else { "-net".into() },
            if host {
                route.destination.addr().to_string()
            } else {
                route.destination.to_string()
            },
        ];
        match route.gateway {
            Some(IpAddr::V6(gateway)) if gateway.is_unicast_link_local() => {
                args.push(format!("{gateway}%{interface}"))
            }
            Some(gateway) => args.push(gateway.to_string()),
            None => args.extend(["-interface".into(), interface.clone()]),
        }
        if matches!(route.scope, RouteScope::Member(_)) {
            args.extend(["-ifscope".into(), interface]);
        }
        self.commands.run("/sbin/route", &args)?;
        Ok(())
    }
}

fn table_destination(text: &str, ipv4: bool) -> Option<IpNet> {
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
    if text.starts_with("link#") {
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
fn physical_interface(name: &str) -> bool {
    !["lo", "utun", "tun", "tap", "wg", "awg", "nlm-"]
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
    }
    impl MacNetworkCommands for Commands {
        fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
            self.calls.push((program.into(), args.to_vec()));
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
            let calls = &native.commands.calls;
            assert_eq!(
                calls[calls.len() - 2].1,
                [
                    "-n",
                    "delete",
                    "-inet6",
                    "-net",
                    cidr,
                    "-interface",
                    "utun10"
                ]
                .map(String::from)
            );
            assert_eq!(
                calls.last().unwrap().1,
                ["-n", "add", "-inet6", "-net", cidr, "-interface", "utun20"].map(String::from)
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
    fn policy_discovers_physical_not_tunnel_gateway_and_preserves_existing_lan() {
        let mut native=MacNetwork {commands:PhysicalCommands {v4:"default 10.0.0.1 UGSc utun10\ndefault 192.168.1.1 UGSc en0\n192.168.1 link#5 UCS en0\n",v6:""}};
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
        assert_eq!(policy.retained_routes.len(), 1);
        assert_eq!(
            policy.retained_routes[0].destination,
            "192.168.1.0/24".parse().unwrap()
        );
        assert_eq!(policy.bypasses.len(), 2);
        assert!(policy
            .bypasses
            .iter()
            .all(|r| r.interface == 5 && r.gateway == Some("192.168.1.1".parse().unwrap())));
        assert!(policy
            .bypasses
            .iter()
            .any(|r| r.destination == "198.51.100.1/32".parse().unwrap()));
        assert!(policy
            .bypasses
            .iter()
            .any(|r| r.destination == "203.0.113.0/24".parse().unwrap()));
    }

    #[test]
    fn discovery_distinguishes_owned_bypass_from_preexisting_identical_route() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "default 192.168.1.1 UGSc en0\n198.51.100.1 192.168.1.1 UGHS en0\n",
                v6: "",
            },
        };
        let endpoint = "198.51.100.1".parse().unwrap();
        let options = nelomai_client_tunnel::DesktopTunnelOptions::default();
        let borrowed = native.resolve_policy(&options, &[endpoint], &[]).unwrap();
        assert!(borrowed.bypasses.is_empty());
        assert_eq!(borrowed.retained_routes.len(), 1);
        let owned = native
            .resolve_policy(&options, &[endpoint], &["198.51.100.1/32".parse().unwrap()])
            .unwrap();
        assert_eq!(owned.bypasses.len(), 1);
        assert!(owned.retained_routes.is_empty());
    }

    #[test]
    fn ipv6_physical_gateway_scope_is_kept_and_ambiguous_egress_is_rejected() {
        let mut native = MacNetwork {
            commands: PhysicalCommands {
                v4: "",
                v6: "default fe80::1%en0 UGcIg en0\n",
            },
        };
        let options = nelomai_client_tunnel::DesktopTunnelOptions::default();
        let policy = native
            .resolve_policy(&options, &["2001:db8::1".parse().unwrap()], &[])
            .unwrap();
        assert_eq!(policy.bypasses[0].gateway, Some("fe80::1".parse().unwrap()));
        assert_eq!(policy.bypasses[0].interface, 5);
        native.commands.v6 = "default fe80::1%en0 UGcIg en0\ndefault fe80::2%en1 UGcIg en1\n";
        assert!(native
            .resolve_policy(&options, &["2001:db8::1".parse().unwrap()], &[])
            .is_err());
    }

    #[test]
    fn ipv6_link_local_gateway_is_read_and_sent_with_its_native_interface_scope() {
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
        native
            .compare_exchange(&value.key(), Some(&value), None)
            .unwrap();
        assert_eq!(
            native
                .commands
                .calls
                .last()
                .unwrap()
                .1
                .last()
                .map(String::as_str),
            Some("fe80::1%utun10")
        );
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
        assert_eq!(policy.bypasses.len(), 1);
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
        assert_eq!(policy.bypasses.len(), 1);
        assert_eq!(policy.retained_routes.len(), 2);
        assert_eq!(policy.retained_routes[1].interface, 6);
    }
}
