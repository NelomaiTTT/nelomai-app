//! Ordinary-mode routes use the same write-ahead owner and checked native
//! adapter as paired mode, but a separate journal and no DNS resources.
use crate::member_network::{
    journal::ScopedJournal,
    macos::{MacNetwork, MacNetworkCommands},
};
use ipnet::IpNet;
use nelomai_client_tunnel::redundancy::{network::*, SessionScope};
use nelomai_contracts::RuntimeSlot;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::{fs, io, net::IpAddr, path::Path};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    boot: String,
    network: NetworkJournal,
}
struct Store {
    file: ScopedJournal<Record>,
    boot: String,
}
impl NetworkJournalStore for Store {
    fn save(&mut self, network: &NetworkJournal) -> io::Result<()> {
        self.file.save_state(&Record {
            boot: self.boot.clone(),
            network: network.clone(),
        })
    }
}

// Even a malformed journal must never confer resolver ownership on this path.
struct RoutesOnly<C>(MacNetwork<C>);
impl<C: MacNetworkCommands> NetworkSystem for RoutesOnly<C> {
    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        if !matches!(key, ResourceKey::Route(_, RouteScope::Global)) {
            return Err(invalid());
        }
        self.0.read(key)
    }
    fn compare_exchange(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
    ) -> io::Result<()> {
        if !matches!(key, ResourceKey::Route(_, RouteScope::Global)) {
            return Err(invalid());
        }
        self.0.compare_exchange(key, before, after)
    }
}

pub(super) struct OrdinaryRoutes<C> {
    owner: Option<NetworkOwner<RoutesOnly<C>, Store>>,
}
impl<C: MacNetworkCommands> OrdinaryRoutes<C> {
    pub(super) fn open(root: &Path, boot: &str, uid: u32, commands: C) -> io::Result<Self> {
        if !valid_boot(boot) {
            return Err(invalid());
        }
        // The existing socket/runtime directory is intentionally searchable
        // (0755). Keep the journal in its own private child, without changing
        // socket access or weakening ScopedJournal's ownership checks.
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid());
        }
        let private = root.join("ordinary-routing");
        match fs::DirBuilder::new().mode(0o700).create(&private) {
            Ok(()) => fs::File::open(root)?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error),
        }
        // Stable namespace for the existing private-file implementation. The
        // runtime root and distinct filename isolate ordinary mode; no pair's
        // session scope, journal, or DNS baseline is shared or adopted.
        let scope = SessionScope {
            runtime: RuntimeSlot::Latest,
            runtime_generation: 1,
            session_id: "00000000-0000-4000-8000-000000000001".into(),
            connection_generation: 1,
        };
        let file = ScopedJournal::open_named(&private, scope, uid, "ordinary-routes.json")?;
        let saved: Option<Record> = file.load()?;
        let mut store = Store {
            file,
            boot: boot.into(),
        };
        let network = match saved {
            Some(saved) => {
                if !valid_boot(&saved.boot) {
                    return Err(invalid());
                }
                if saved.boot.eq_ignore_ascii_case(boot) {
                    saved.network
                } else {
                    // Routes are ephemeral across boots. Never query/delete
                    // rows through a reused native index from the old boot.
                    store.save(&NetworkJournal::default())?;
                    NetworkJournal::default()
                }
            }
            None => NetworkJournal::default(),
        };
        let owner = NetworkOwner::recover(RoutesOnly(MacNetwork { commands }), store, network)?;
        Ok(Self { owner: Some(owner) })
    }

    pub(super) fn install(
        &mut self,
        interface: &str,
        allowed: &[IpNet],
        endpoints: &[IpAddr],
    ) -> io::Result<()> {
        if self.has_resources() {
            return Err(io::Error::other("ordinary_route_cleanup_pending"));
        }
        // A successful Stop fences NetworkOwner permanently. A new ordinary
        // attempt may start only after that owner's resources are all gone.
        let (system, store) = self.owner.take().expect("route owner").into_parts();
        self.owner = Some(NetworkOwner::fresh(system, store));
        let owner = self.owner.as_mut().expect("route owner");
        let native = &mut owner.system_mut().0;
        if !interface
            .strip_prefix("utun")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            || allowed.is_empty()
            || allowed.len() > 32768
            || endpoints.is_empty()
            || endpoints.len() > 32768
        {
            return Err(invalid());
        }
        let index = native.commands.interface_index(interface)?;
        let mut values = Vec::new();
        let mut retained = Vec::new();
        let mut endpoints = endpoints.to_vec();
        endpoints.sort();
        endpoints.dedup();
        for endpoint in &endpoints {
            let route = physical_endpoint(&mut native.commands, *endpoint)?;
            let value = NetworkValue::Route(route);
            match native.read(&value.key())? {
                None => values.push(value),
                Some(existing) if existing == value => retained.push(value),
                Some(_) => return Err(io::Error::other("ordinary_endpoint_route_conflict")),
            }
        }
        let mut destinations = Vec::new();
        for network in allowed {
            if network.prefix_len() == 0 {
                let halves = if network.addr().is_ipv4() {
                    ["0.0.0.0/1", "128.0.0.0/1"]
                } else {
                    ["::/1", "8000::/1"]
                };
                destinations.extend(halves.map(|s| s.parse::<IpNet>().expect("constant CIDR")));
            } else {
                destinations.push(network.trunc());
            }
        }
        destinations.sort();
        destinations.dedup();
        for destination in destinations {
            // Endpoint bypass wins over an exact AllowedIPs host route too.
            if endpoints.iter().any(|e| IpNet::from(*e) == destination) {
                continue;
            }
            values.push(NetworkValue::Route(RouteValue {
                destination,
                scope: RouteScope::Global,
                interface: index,
                gateway: None,
                metric: 0,
            }));
        }
        // NetworkOwner rejects every preexisting data-route key (even an
        // identical utun row), before writing intent or changing any route.
        owner.prepare(values.clone())?;
        let verified = (|| {
            let native = &mut owner.system_mut().0;
            // Recheck retained dependencies and the entire installed set,
            // including rows changed while later additions were in progress.
            for value in retained.iter().chain(&values) {
                if native.read(&value.key())?.as_ref() != Some(value) {
                    return Err(io::Error::other("ordinary_route_readback_failed"));
                }
            }
            for endpoint in endpoints {
                let actual =
                    NetworkValue::Route(physical_endpoint(&mut native.commands, endpoint)?);
                if !retained.iter().chain(&values).any(|value| *value == actual) {
                    return Err(io::Error::other("ordinary_endpoint_route_changed"));
                }
            }
            Ok(())
        })();
        if verified.is_err() {
            let _ = owner.cleanup();
        }
        verified
    }

    pub(super) fn cleanup(&mut self) -> io::Result<()> {
        if self.has_resources() {
            self.owner.as_mut().expect("route owner").cleanup()?;
        }
        Ok(())
    }
    pub(super) fn has_resources(&self) -> bool {
        self.owner.as_ref().expect("route owner").has_resources()
    }
}

fn physical_endpoint<C: MacNetworkCommands>(
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
    let field = |name: &str| -> io::Result<&str> {
        let mut matches = text.lines().filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == name).then_some(value.trim())
        });
        let value = matches.next().ok_or_else(invalid)?;
        if matches.next().is_some() || value.is_empty() {
            return Err(invalid());
        }
        Ok(value)
    };
    let name = field("interface")?;
    if ["lo", "utun", "tun", "tap", "wg", "awg", "nlm-"]
        .iter()
        .any(|p| name.starts_with(p))
    {
        return Err(invalid());
    }
    let flags = field("flags")?
        .trim_matches(['<', '>'])
        .split(',')
        .collect::<Vec<_>>();
    if !flags.contains(&"UP") || flags.iter().any(|f| matches!(*f, "REJECT" | "BLACKHOLE")) {
        return Err(invalid());
    }
    let gateway = field("gateway")?;
    let gateway = if gateway.starts_with("link#") {
        None
    } else {
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
    };
    Ok(RouteValue {
        destination: endpoint.into(),
        scope: RouteScope::Global,
        interface: commands.interface_index(name)?,
        gateway,
        metric: 0,
    })
}
fn valid_boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid_ordinary_route_state")
}

#[cfg(test)]
mod tests;
