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
                    let gateway = if fields[1].starts_with("link#") {
                        None
                    } else {
                        Some(fields[1].parse::<IpAddr>().map_err(|_| invalid())?)
                    };
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
}
