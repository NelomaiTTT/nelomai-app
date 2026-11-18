//! Ordinary-mode routes use the same write-ahead owner and checked native
//! adapter as paired mode, but a separate journal and no DNS resources.
use crate::member_network::{
    journal::ScopedJournal,
    macos::{
        physical_endpoint, physical_interface, table_destination, MacNetwork, MacNetworkCommands,
    },
};
use ipnet::IpNet;
use nelomai_client_tunnel::redundancy::{driver::RouteRefreshError, network::*, SessionScope};
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
    fn journal_each_write(&self) -> bool {
        true
    }

    fn observe_routes_on_close(&self) -> bool {
        true
    }

    fn read(&mut self, key: &ResourceKey) -> io::Result<Option<NetworkValue>> {
        if !matches!(key, ResourceKey::Route(_, RouteScope::Global)) {
            return Err(invalid());
        }
        self.0.read(key)
    }
    fn read_many(&mut self, keys: &[ResourceKey]) -> io::Result<Vec<Option<NetworkValue>>> {
        if keys
            .iter()
            .any(|key| !matches!(key, ResourceKey::Route(_, RouteScope::Global)))
        {
            return Err(invalid());
        }
        self.0.read_many(keys)
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

    fn compare_exchange_prepared(
        &mut self,
        key: &ResourceKey,
        before: Option<&NetworkValue>,
        after: Option<&NetworkValue>,
        prepare: Option<&mut dyn FnMut() -> io::Result<()>>,
    ) -> Result<(), RouteRefreshError> {
        if !matches!(key, ResourceKey::Route(_, RouteScope::Global)) {
            return Err(RouteRefreshError::Unchanged(invalid()));
        }
        self.0
            .compare_exchange_prepared(key, before, after, prepare)
    }
}

pub(super) fn ordinary_journal_location(
    root: &Path,
    uid: u32,
) -> io::Result<(std::path::PathBuf, SessionScope)> {
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
    Ok((private, scope))
}

pub(super) struct OrdinaryRoutes<C> {
    owner: Option<NetworkOwner<RoutesOnly<C>, Store>>,
}
impl<C: MacNetworkCommands> OrdinaryRoutes<C> {
    pub(super) fn open(root: &Path, boot: &str, uid: u32, commands: C) -> io::Result<Self> {
        if !valid_boot(boot) {
            return Err(invalid());
        }
        let (private, scope) = ordinary_journal_location(root, uid)?;
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
                    saved.network.unix_recovery()?
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
        split: &nelomai_client_tunnel::Ipv4RoutePlan,
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
        let mut endpoints = endpoints.to_vec();
        endpoints.sort();
        endpoints.dedup();
        let physical = endpoints
            .iter()
            .map(|ip| physical_endpoint(&mut native.commands, *ip))
            .collect::<io::Result<Vec<_>>>()?;
        let mut holes: Vec<_> = split
            .excluded_networks
            .iter()
            .copied()
            .map(IpNet::V4)
            .collect();
        holes.extend(endpoints.iter().copied().map(IpNet::from));
        crate::member_network::macos::preserve_scoped_defaults(&mut holes);
        let mut existing = Vec::new();
        for (ipv4, family) in [(true, "inet"), (false, "inet6")] {
            if !allowed.iter().any(|net| net.addr().is_ipv4() == ipv4) {
                continue;
            }
            let table = native.commands.run(
                "/usr/sbin/netstat",
                &["-rn".into(), "-f".into(), family.into()],
            )?;
            for row in table.lines() {
                let mut fields = row.split_whitespace();
                if let (Some(dst), Some(gateway), Some(flags), Some(interface)) =
                    (fields.next(), fields.next(), fields.next(), fields.next())
                {
                    if !flags.contains('I') {
                        if let Some(net) = table_destination(dst, ipv4) {
                            existing.push(net);
                            if split.exclude_local_networks
                                && physical_interface(interface)
                                && gateway.starts_with("link#")
                                && net.prefix_len() > 0
                                && net.prefix_len() < if ipv4 { 32 } else { 128 }
                            {
                                holes.push(net);
                            }
                        }
                    }
                }
            }
        }
        let destinations =
            nelomai_client_tunnel::redundancy::route_plan::tunnel_destinations_preserving(
                allowed, &holes, &existing,
            )?;
        let values: Vec<_> = destinations
            .into_iter()
            .map(|destination| {
                NetworkValue::Route(RouteValue {
                    destination,
                    scope: RouteScope::Global,
                    interface: index,
                    gateway: None,
                    metric: 0,
                })
            })
            .collect();
        // NetworkOwner rejects every preexisting data-route key (even an
        // identical utun row), before writing intent or changing any route.
        owner.prepare(values.clone())?;
        (|| {
            let native = &mut owner.system_mut().0;
            let keys: Vec<_> = values.iter().map(NetworkValue::key).collect();
            let current = native.read_many(&keys)?;
            if current.len() != keys.len()
                || current
                    .iter()
                    .map(Option::as_ref)
                    .ne(values.iter().map(Some))
            {
                return Err(io::Error::other("ordinary_route_readback_failed"));
            }
            for (ip, expected) in endpoints.into_iter().zip(physical) {
                if physical_endpoint(&mut native.commands, ip)? != expected {
                    return Err(io::Error::other("ordinary_endpoint_route_changed"));
                }
            }
            Ok(())
        })()
    }

    pub(super) fn cleanup(&mut self) -> io::Result<()> {
        if self.has_resources() {
            self.owner.as_mut().expect("route owner").cleanup()?;
        }
        Ok(())
    }
    pub(super) fn confirm_link_closed(&mut self) -> io::Result<()> {
        self.owner
            .as_mut()
            .expect("route owner")
            .confirm_links_closed()
    }
    pub(super) fn has_resources(&self) -> bool {
        self.owner.as_ref().expect("route owner").has_resources()
    }
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
