use super::macos_launch::{self, ManagedUtun};
use super::member_owner::{MemberOwner, MemberTransport, UserspaceIdentity};
use super::redundancy::ResourceMode;
use super::{
    append_userspace_log, apply_and_verify_awg3_configuration, build_backend_configuration,
    configure_interface_after_awg3, host_diagnostic_snapshot, rebind_peers_for_start,
    rebind_peers_from_host, rebind_userspace_udp, state_name, transport_name,
    userspace_log_streams, userspace_socket_path, DiagnosticJournal, RebindPeer,
};
#[cfg(test)]
use crate::process::{output_with_timeout, COMMAND_TIMEOUT};
use crate::routes::{
    endpoint_route_summary, verify_endpoint_routes, RouteManager, SystemRouteBackend,
};
use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use defguard_wireguard_rs::{Userspace, WGApi, WireguardInterfaceApi};
use nelomai_client_tunnel::{DesktopTunnelOptions, TunnelMetrics, TunnelTransport};
use nelomai_contracts::dispatcher::TunnelSlot;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Output;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[cfg(test)]
const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const INTERFACE_STATE_FILE: &str = "interface-name";
const DNS_STATE_FILE: &str = "dns-state.json";
const ENDPOINTS_STATE_FILE: &str = "endpoints-state.json";
const START_TIMEOUT: Duration = Duration::from_secs(3);

mod dns;
mod launch_listener;
mod ordinary_routes;
mod utun;
use crate::member_network::macos::{MacNetworkCommands, NativeMacCommands};
use launch_listener::ListenerOwner;
use ordinary_routes::OrdinaryRoutes;

pub struct MacosBackend {
    mode: ResourceMode,
    forward_nat: crate::forward_nat::Owner<
        crate::forward_nat::macos::Adapter<crate::forward_nat::NativeCommands>,
    >,
    nat_refresh_at: Option<Instant>,
    nat_interface: Option<(String, u32)>,
    nat_unavailable: bool,
    transport_owner: MemberOwner,
    custody: Option<UtunCustody>,
    wireguard_go: PathBuf,
    amneziawg_go: PathBuf,
    runtime_directory: PathBuf,
    api: Option<WGApi<Userspace>>,
    active_transport: Option<TunnelTransport>,
    rebind_peers: Vec<RebindPeer>,
    endpoints: Vec<SocketAddr>,
    dns_snapshot: Option<DnsSnapshot>,
    routes: RouteManager<SystemRouteBackend>,
    ordinary_routes: Option<OrdinaryRoutes<NativeMacCommands>>,
    state: ServiceTunnelState,
    diagnostics: DiagnosticJournal,
}

// Keep both the name and the daemon tied to this service. Losing the service
// closes the guardian endpoint, which terminates the engine's process group.
struct UtunCustody {
    engine: utun::GuardedEngine,
    utun: utun::Utun,
    socket: super::redundancy::SocketIdentity,
}

impl MacosBackend {
    pub fn new(
        wireguard_go: impl Into<PathBuf>,
        amneziawg_go: impl Into<PathBuf>,
        runtime_directory: impl Into<PathBuf>,
    ) -> Result<Self, ServiceError> {
        Self::with_mode(
            wireguard_go.into(),
            amneziawg_go.into(),
            &runtime_directory.into(),
            ResourceMode::Single,
            None,
        )
    }

    /// The session owns routes/DNS and creates this private slot directory first.
    pub fn new_member(
        wireguard_go: impl Into<PathBuf>,
        amneziawg_go: impl Into<PathBuf>,
        runtime_directory: &Path,
        slot: TunnelSlot,
        scope: nelomai_client_tunnel::redundancy::SessionScope,
    ) -> Result<Self, ServiceError> {
        let owner = MemberOwner::open_root(
            &ResourceMode::Member(slot).runtime_path(runtime_directory),
            scope,
            slot,
        )
        .map_err(backend_error)?;
        Self::with_mode(
            wireguard_go.into(),
            amneziawg_go.into(),
            runtime_directory,
            ResourceMode::Member(slot),
            Some(owner),
        )
    }

    fn with_mode(
        wireguard_go: PathBuf,
        amneziawg_go: PathBuf,
        root: &Path,
        mode: ResourceMode,
        member_owner: Option<MemberOwner>,
    ) -> Result<Self, ServiceError> {
        let runtime_directory = mode.runtime_path(root);
        let routes = RouteManager::new(&runtime_directory, SystemRouteBackend::new()?)?;
        let ordinary_routes = if mode.owns_network() {
            Some(
                OrdinaryRoutes::open(&runtime_directory, &boot_identity()?, 0, NativeMacCommands)
                    .map_err(backend_error)?,
            )
        } else {
            None
        };
        let dns_snapshot = if mode.owns_network() {
            load_dns_snapshot(&runtime_directory.join(DNS_STATE_FILE))?
        } else {
            None
        };
        let forward_nat = crate::forward_nat::Owner::open(
            &runtime_directory,
            &boot_identity()?,
            0,
            crate::forward_nat::macos::Adapter::new(crate::forward_nat::NativeCommands::default()),
        )
        .map_err(backend_error)?;
        let mut transport_owner = match member_owner {
            Some(owner) => owner,
            None => {
                let (private, scope) =
                    ordinary_routes::ordinary_journal_location(&runtime_directory, 0)
                        .map_err(backend_error)?;
                MemberOwner::open_named(
                    &private,
                    scope,
                    TunnelSlot::A,
                    0,
                    "ordinary-userspace.json",
                )
                .map_err(backend_error)?
            }
        };
        let boot = boot_identity()?;
        let recovered = if transport_owner.manages_utun() {
            Ok(None) // The previous service's guardian is ending its daemon.
        } else {
            prepare_legacy_owner(
                &mut transport_owner,
                mode,
                &runtime_directory,
                &boot,
                &wireguard_go,
                &amneziawg_go,
            )
            .and_then(|()| {
                if transport_owner.stopping() {
                    return Ok(None);
                }
                transport_owner
                    .recover(&boot, |saved| inspect_member(saved, &boot))
                    .map_err(backend_error)
            })
        };
        let (active_transport, native_pending) = match recovered {
            Ok(active) => (
                active.map(|transport| match transport {
                    MemberTransport::WireGuard => TunnelTransport::WireGuard,
                    MemberTransport::AmneziaWg3 => TunnelTransport::AmneziaWg3,
                }),
                false,
            ),
            // Keep Stop available for ordinary routes/DNS and for captured
            // members whose listener disappeared before the kernel detached.
            Err(_) if mode.owns_network() || transport_owner.identity().is_some() => (None, true),
            Err(error) => return Err(error),
        };
        let api = if active_transport.is_some() && !transport_owner.stopping() {
            let name = &transport_owner
                .identity()
                .expect("verified userspace owner")
                .interface;
            Some(WGApi::<Userspace>::new(name).map_err(backend_error)?)
        } else {
            None
        };
        let rebind_peers = api
            .as_ref()
            .and_then(|api| api.read_interface_data().ok())
            .as_ref()
            .map(rebind_peers_from_host)
            .unwrap_or_default();
        let endpoints = if api.is_some() {
            load_endpoints(&runtime_directory.join(ENDPOINTS_STATE_FILE))?
        } else {
            Vec::new()
        };
        let state = if native_pending
            || (api.is_none() && transport_owner.cleanup_pending())
            || (transport_owner.stopping() && !mode.owns_network())
            || forward_nat.is_recovering()
            || ordinary_routes
                .as_ref()
                .is_some_and(OrdinaryRoutes::has_resources)
        {
            ServiceTunnelState::Stopping
        } else if api.is_some() {
            ServiceTunnelState::Running
        } else {
            ServiceTunnelState::Stopped
        };
        let mut diagnostics = DiagnosticJournal::default();
        diagnostics.record(
            "helper_initialized",
            &format!(
                "state={} transport={}",
                state_name(state),
                if api.is_some() { "unknown" } else { "none" }
            ),
        );
        let mut backend = Self {
            mode,
            forward_nat,
            nat_refresh_at: None,
            nat_interface: None,
            nat_unavailable: false,
            transport_owner,
            custody: None,
            wireguard_go,
            amneziawg_go,
            runtime_directory,
            api,
            active_transport,
            rebind_peers,
            endpoints,
            dns_snapshot,
            routes,
            ordinary_routes,
            state,
            diagnostics,
        };
        if mode.owns_network() && backend.api.is_none() {
            // Cleanup paths remain independent, even if an old link cannot be proven.
            if backend.cleanup_ordinary_network().is_err() {
                backend.state = ServiceTunnelState::Stopping;
            }
        }
        Ok(backend)
    }

    fn start_inner(
        &mut self,
        configuration: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<(), ServiceError> {
        if self.mode.owns_network() && !self.transport_owner.manages_utun() {
            prepare_legacy_owner(
                &mut self.transport_owner,
                self.mode,
                &self.runtime_directory,
                &boot_identity()?,
                &self.wireguard_go,
                &self.amneziawg_go,
            )?;
        }
        if self.transport_owner.cleanup_pending()
            || self.forward_nat.has_resources()
            || self.api.is_some()
            || self.dns_snapshot.is_some()
            || self.routes.has_routes()
            || self
                .ordinary_routes
                .as_ref()
                .is_some_and(OrdinaryRoutes::has_resources)
        {
            self.stop_inner()?;
        }
        let executable = match configuration.transport {
            TunnelTransport::WireGuard => self.wireguard_go.clone(),
            TunnelTransport::AmneziaWg3 => self.amneziawg_go.clone(),
        };
        validate_root_owned_binary(&executable)?;
        validate_runtime_directory(&self.runtime_directory)?;

        let mut native = build_backend_configuration(configuration)?;
        let split = nelomai_client_tunnel::Ipv4RoutePlan::from_options(options)
            .map_err(|error| backend_error(error.stable_code()))?;
        if !self.mode.owns_network() {
            native.interface.port = 0;
        } else if !configuration.dns.is_empty() {
            self.capture_dns(&configuration.dns)?;
        }
        let mut receipt = macos_launch::new_receipt(
            match configuration.transport {
                TunnelTransport::WireGuard => MemberTransport::WireGuard,
                TunnelTransport::AmneziaWg3 => MemberTransport::AmneziaWg3,
            },
            &executable,
        )
        .map_err(backend_error)?;
        let utun = launch_listener::open_available_utun().map_err(backend_error)?;
        let ifname = utun.name().to_owned();
        let native_index = utun.ifindex();
        receipt.managed = Some(ManagedUtun {
            name: ifname.clone(),
            index: native_index,
            socket: None,
        });
        self.transport_owner
            .begin(receipt.clone())
            .map_err(backend_error)?;
        let listener = launch_listener::LaunchListener::bind(&receipt).map_err(backend_error)?;
        self.transport_owner
            .record_managed_listener(listener.identity)
            .map_err(backend_error)?;
        // The journal precedes the public socket and the child handoff. Both
        // descriptors stay private until the proven executable inherits them.
        listener.publish().map_err(backend_error)?;
        let engine = launch_userspace_tunnel(&self.runtime_directory, &receipt, &utun, &listener)?;
        self.custody = Some(UtunCustody {
            engine,
            utun,
            socket: listener.identity,
        });
        let proof = macos_launch::prove(
            &self.runtime_directory,
            self.transport_owner.receipt().expect("launch receipt"),
            self.mode.owns_network(),
        )
        .map_err(backend_error)?;
        self.transport_owner
            .capture_proven(proof, false)
            .map_err(backend_error)?;
        self.active_transport = Some(configuration.transport);
        native.interface.name = ifname.clone();
        let api = WGApi::<Userspace>::new(&ifname).map_err(backend_error)?;
        self.endpoints = native.endpoints;
        self.api = Some(api);
        self.nat_interface = Some((ifname.clone(), native_index));
        save_endpoints(
            &self.runtime_directory.join(ENDPOINTS_STATE_FILE),
            &self.endpoints,
        )?;

        let configured = configure_interface_after_awg3(
            configuration.awg3.as_ref(),
            |parameters| apply_and_verify_awg3_configuration(&ifname, parameters),
            || {
                self.api
                    .as_ref()
                    .expect("WireGuard API assigned")
                    .configure_interface(&native.interface)
                    .map_err(backend_error)
            },
        );
        native.interface.prvkey.zeroize();
        configured?;
        if self.mode.owns_network() {
            let allowed = configuration
                .peers
                .iter()
                .flat_map(|peer| peer.allowed_ips.iter().copied())
                .collect::<Vec<_>>();
            let endpoints = self
                .endpoints
                .iter()
                .map(SocketAddr::ip)
                .collect::<Vec<_>>();
            self.ordinary_routes
                .as_mut()
                .expect("ordinary route owner")
                .install(&ifname, &allowed, &endpoints, &split)
                .map_err(backend_error)?;
        }
        if configuration.transport == TunnelTransport::AmneziaWg3 {
            verify_endpoint_routes(&self.endpoints)?;
        }
        self.apply_dns()?;
        self.refresh_forward_nat()?;
        self.rebind_peers = rebind_peers_for_start(configuration, self.mode);
        Ok(())
    }

    fn refresh_forward_nat(&mut self) -> Result<(), ServiceError> {
        // A reopened ordinary UAPI alone is not fresh ownership of its utun.
        // A new VPN Start captures the interface incarnation before configuring it.
        let Some(binding) = self.nat_interface.as_ref() else {
            return Ok(());
        };
        let Some(api) = self.api.as_ref() else {
            return Ok(());
        };
        let identity = self.verified_identity()?;
        let name = identity.interface.clone();
        api.read_interface_data().map_err(backend_error)?;
        let index = NativeMacCommands
            .interface_index(&name)
            .map_err(backend_error)?;
        verify_nat_binding(binding, &name, index).map_err(backend_error)?;
        match self.forward_nat.refresh(&name, index) {
            Ok(()) => {
                self.nat_unavailable = false;
                Ok(())
            }
            Err(error)
                if !self.forward_nat.has_resources()
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::Unsupported | std::io::ErrorKind::NotFound
                    ) =>
            {
                // NAT compatibility is optional on custom PF/minimal Linux hosts.
                // Never disable an otherwise working host VPN for an absent tool.
                if !self.nat_unavailable {
                    self.diagnostics
                        .record("vm_nat_unavailable", "native_support_unavailable");
                }
                self.nat_unavailable = true;
                Ok(())
            }
            Err(error) => Err(backend_error(error)),
        }
    }

    fn stop_inner(&mut self) -> Result<(), ServiceError> {
        let nat = self.forward_nat.cleanup().map_err(backend_error);
        let native = self.stop_native_inner();
        if native.is_ok() {
            self.nat_interface = None;
        }
        self.nat_refresh_at = None;
        nat.and(native)
    }

    fn stop_native_inner(&mut self) -> Result<(), ServiceError> {
        let transport = (|| {
            let boot = boot_identity()?;
            if self.transport_owner.manages_utun() {
                return self.stop_managed_transport(&boot);
            }
            prepare_legacy_owner(
                &mut self.transport_owner,
                self.mode,
                &self.runtime_directory,
                &boot,
                &self.wireguard_go,
                &self.amneziawg_go,
            )?;
            self.transport_owner
                .stop_owned(&boot, inspect_member_for_stop, stop_member)
                .map_err(backend_error)
        })();
        if !self.mode.owns_network() && transport.is_err() {
            return transport;
        }
        self.api = None;
        self.active_transport = None;
        self.rebind_peers.clear();
        if !self.mode.owns_network() {
            self.endpoints.clear();
            return Ok(());
        }
        let network = self.cleanup_ordinary_network();
        // An interrupted launch still needs its state file to prove the peer.
        if transport.is_ok() {
            remove_regular_file_if_present(&self.runtime_directory.join(INTERFACE_STATE_FILE))
                .map_err(backend_error)?;
        }
        transport.and(network)
    }

    fn stop_managed_transport(&mut self, boot: &str) -> Result<(), ServiceError> {
        // The local control descriptor still excludes any competing owner of
        // the name during unlink. Across a service crash, only bind-only
        // reservation in the orphan cleanup below grants authority to unlink.
        let stopping = self
            .transport_owner
            .identity()
            .is_some()
            .then(|| self.transport_owner.begin_stop());
        if let Some(custody) = &mut self.custody {
            let path = userspace_socket_path(custody.utun.name());
            launch_listener::unlink_if_owned(&path, custody.socket).map_err(backend_error)?;
            custody.engine.stop().map_err(backend_error)?;
        }
        drop(self.custody.take());
        self.transport_owner
            .retire_starting_after_boot(boot)
            .map_err(backend_error)?;
        if let Some(receipt) = self.transport_owner.receipt() {
            launch_listener::retire(receipt).map_err(backend_error)?;
            return self
                .transport_owner
                .retire_managed_launch()
                .map_err(backend_error);
        }
        if let Some(owned) = self
            .transport_owner
            .identity()
            .filter(|owned| owned.boot == boot)
        {
            launch_listener::retire_public(
                &owned.interface,
                owned.index,
                owned.socket,
                ListenerOwner::Verified(
                    self.transport_owner
                        .managed_process()
                        .expect("managed daemon identity"),
                ),
            )
            .map_err(backend_error)?;
        }
        if let Some(stopping) = stopping {
            stopping.map_err(backend_error)?;
            if let Some(routes) = &mut self.ordinary_routes {
                routes.confirm_link_closed().map_err(backend_error)?;
            }
            self.transport_owner.finish_stop().map_err(backend_error)?;
        }
        Ok(())
    }

    fn cleanup_ordinary_network(&mut self) -> Result<(), ServiceError> {
        let mut first_error = None;
        // Endpoint lists from older helpers are metadata, never ownership
        // proof. Only the new write-ahead journal authorizes route deletion.
        let ordinary_clean = if let Some(routes) = &mut self.ordinary_routes {
            match routes.cleanup() {
                Ok(()) => true,
                Err(error) => {
                    first_error.get_or_insert_with(|| backend_error(error));
                    false
                }
            }
        } else {
            true
        };
        if let Err(error) = self.restore_dns() {
            first_error.get_or_insert(error);
        }
        if ordinary_clean {
            if let Err(error) =
                remove_regular_file_if_present(&self.runtime_directory.join(ENDPOINTS_STATE_FILE))
            {
                first_error.get_or_insert_with(|| backend_error(error));
            } else {
                self.endpoints.clear();
            }
        }
        if let Err(error) = self.routes.cleanup() {
            first_error.get_or_insert(error);
        }

        first_error.map_or(Ok(()), Err)
    }

    fn verified_identity(&self) -> Result<&UserspaceIdentity, ServiceError> {
        let boot = boot_identity()?;
        self.transport_owner
            .recover(&boot, |saved| inspect_member(saved, &boot))
            .map_err(backend_error)?
            .ok_or_else(|| backend_error("userspace_interface_unavailable"))?;
        Ok(self
            .transport_owner
            .identity()
            .expect("verified userspace owner"))
    }

    fn capture_dns(&mut self, servers: &[IpAddr]) -> Result<(), ServiceError> {
        let snapshot = DnsSnapshot {
            services: dns::snapshot().map_err(backend_error)?,
            intent: Some(DnsIntent::new(servers)?),
        };
        self.dns_snapshot = Some(snapshot);
        save_json_state(
            &self.runtime_directory.join(DNS_STATE_FILE),
            self.dns_snapshot.as_ref().expect("captured DNS snapshot"),
        )?;
        fs::File::open(&self.runtime_directory)
            .and_then(|directory| directory.sync_all())
            .map_err(backend_error)?;
        Ok(())
    }

    fn apply_dns(&self) -> Result<(), ServiceError> {
        if let Some(snapshot) = &self.dns_snapshot {
            let intent = snapshot.intent.as_ref().expect("captured DNS write intent");
            dns::apply(&snapshot.services, intent).map_err(backend_error)?;
        }
        Ok(())
    }

    fn restore_dns(&mut self) -> Result<(), ServiceError> {
        let Some(snapshot) = self.dns_snapshot.as_ref() else {
            return Ok(());
        };
        restore_dns_snapshot(snapshot)?;
        remove_regular_file_if_present(&self.runtime_directory.join(DNS_STATE_FILE))
            .map_err(backend_error)?;
        self.dns_snapshot = None;
        Ok(())
    }

    fn diagnostic_snapshot(&self) -> String {
        let transport = if self.active_transport.is_none() && self.api.is_some() {
            "unknown"
        } else {
            transport_name(self.active_transport)
        };
        let mut snapshot = format!(
            "state={}\ntransport={transport}\nroutes_active={}\ndns_snapshot_active={}\n{}",
            state_name(self.state),
            self.routes.has_routes()
                || self
                    .ordinary_routes
                    .as_ref()
                    .is_some_and(OrdinaryRoutes::has_resources),
            self.dns_snapshot.is_some(),
            endpoint_route_summary(&self.endpoints),
        );
        match self
            .api
            .as_ref()
            .ok_or_else(|| ServiceError::Backend("tunnel_not_running".to_string()))
            .and_then(|api| {
                if self.mode.owns_network() {
                    self.verified_identity()?;
                }
                api.read_interface_data().map_err(backend_error)
            }) {
            Ok(host) => {
                snapshot.push('\n');
                snapshot.push_str(&host_diagnostic_snapshot(&host));
            }
            Err(error) => {
                snapshot.push_str("\nuapi=unavailable\nuapi_error_code=");
                snapshot.push_str(error.code());
            }
        }
        snapshot
    }
}

impl ServiceTunnelBackend for MacosBackend {
    fn member_recovery_scope(&self) -> Option<nelomai_client_tunnel::redundancy::SessionScope> {
        (!self.mode.owns_network()).then(|| self.transport_owner.scope.clone())
    }
    fn member_cleanup_pending(&self) -> bool {
        self.forward_nat.is_recovering()
            || (!self.mode.owns_network() && self.transport_owner.cleanup_pending())
    }
    fn member_slot(&self) -> Option<TunnelSlot> {
        match self.mode {
            ResourceMode::Single => None,
            ResourceMode::Member(slot) => Some(slot),
        }
    }
    fn member_interface_index(&self) -> Result<u32, ServiceError> {
        if self.mode.owns_network() || self.api.is_none() {
            return Err(ServiceError::Backend("member_interface_unavailable".into()));
        }
        if self.transport_owner.stopping() {
            return Err(ServiceError::Backend("member_not_running".into()));
        }
        let owned = self.verified_identity()?;
        if self.custody.is_some() {
            // The service pins both kernel identity and socket ownership. A
            // crashed daemon can therefore leave both visible while dead.
            macos_launch::probe_listener(&userspace_socket_path(&owned.interface))
                .map_err(|_| backend_error("member_not_running"))?;
        }
        Ok(owned.index)
    }
    fn start(
        &mut self,
        configuration: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        // Reject before the failure-cleanup path: duplicate Start must not tear
        // down the already-owned member it attempted to replace.
        if !self.mode.owns_network() {
            self.transport_owner.ensure_fresh().map_err(backend_error)?;
        }
        self.state = ServiceTunnelState::Starting;
        self.diagnostics.record(
            "start_begin",
            &format!(
                "transport={}",
                transport_name(Some(configuration.transport))
            ),
        );
        match self.start_inner(configuration, options) {
            Ok(()) => {
                self.state = ServiceTunnelState::Running;
                let snapshot = self.diagnostic_snapshot().replace('\n', " ");
                self.diagnostics.record("start_ok", &snapshot);
                Ok(self.state)
            }
            Err(error) => {
                let _ = self.stop_inner();
                self.state = ServiceTunnelState::Failed;
                self.diagnostics
                    .record("start_error", &format!("code={}", error.code()));
                Err(error)
            }
        }
    }

    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.state = ServiceTunnelState::Stopping;
        let snapshot = self.diagnostic_snapshot().replace('\n', " ");
        self.diagnostics.record("stop_begin", &snapshot);
        match self.stop_inner() {
            Ok(()) => {
                self.state = ServiceTunnelState::Stopped;
                self.diagnostics.record("stop_ok", "");
                Ok(self.state)
            }
            Err(error) => {
                self.state = ServiceTunnelState::Failed;
                self.diagnostics
                    .record("stop_error", &format!("code={}", error.code()));
                Err(error)
            }
        }
    }

    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        if self.forward_nat.is_recovering() {
            return Ok(ServiceTunnelState::Stopping);
        }
        if let Some(api) = &self.api {
            if (self.mode.owns_network() && self.verified_identity().is_err())
                || api.read_interface_data().is_err()
            {
                return Ok(ServiceTunnelState::Failed);
            }
        }
        if self.api.is_none()
            && (self.routes.has_routes()
                || self
                    .ordinary_routes
                    .as_ref()
                    .is_some_and(OrdinaryRoutes::has_resources))
        {
            return Ok(ServiceTunnelState::Failed);
        }
        Ok(self.state)
    }

    fn tick(&mut self, _now_ms: u64) -> Result<(), ServiceError> {
        if self.state != ServiceTunnelState::Running
            || self
                .nat_refresh_at
                .is_some_and(|last| last.elapsed() < Duration::from_secs(2))
        {
            return Ok(());
        }
        self.nat_refresh_at = Some(Instant::now());
        self.refresh_forward_nat()
    }

    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        self.routes.physical_network_fingerprint()
    }

    fn metrics(&self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
        if self.mode.owns_network() {
            self.verified_identity()?;
        }
        let host = self
            .api
            .as_ref()
            .ok_or_else(|| ServiceError::Backend("tunnel_not_running".to_string()))?
            .read_interface_data()
            .map_err(backend_error)?;
        let received_bytes = host
            .peers
            .values()
            .fold(0u64, |total, peer| total.saturating_add(peer.rx_bytes));
        let sent_bytes = host
            .peers
            .values()
            .fold(0u64, |total, peer| total.saturating_add(peer.tx_bytes));
        let latest_handshake_epoch_millis = host
            .peers
            .values()
            .filter_map(|peer| peer.last_handshake)
            .filter_map(|handshake| handshake.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .filter(|timestamp| *timestamp > 0)
            .max();
        let probe_target = probe
            .then(|| {
                host.peers
                    .values()
                    .find_map(|peer| peer.endpoint.map(|endpoint| endpoint.ip().to_string()))
            })
            .flatten();
        Ok(TunnelMetrics {
            received_bytes,
            sent_bytes,
            latest_handshake_epoch_millis,
            probe_target,
        })
    }

    fn macos_probe_path(&self) -> Option<crate::MacosProbePath> {
        use crate::member_network::counters;
        if !self.mode.owns_network()
            || self.state != ServiceTunnelState::Running
            || self.transport_owner.stopping()
        {
            return None;
        }
        let owner = self.verified_identity().ok()?;
        let data = counters::native(owner.index).ok()?;
        if self.verified_identity().ok()? != owner {
            return None;
        }
        Some(crate::MacosProbePath {
            interface: owner.interface.clone(),
            index: owner.index,
            socket_device: owner.socket.device,
            socket_inode: owner.socket.inode,
            sent_ip_packets: data.sent_packets,
            received_ip_packets: data.received_packets,
        })
    }

    fn diagnostics(&self) -> Result<String, ServiceError> {
        let mut output = self.diagnostics.render(&self.diagnostic_snapshot());
        append_userspace_log(&mut output, &self.runtime_directory);
        Ok(output)
    }

    fn rebind_udp(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        if self.api.is_none() || self.transport_owner.stopping() {
            return Err(backend_error("tunnel_not_running"));
        }
        let ifname = self.verified_identity()?.interface.clone();
        let before = self.diagnostic_snapshot().replace('\n', " ");
        self.diagnostics.record("udp_rebind_begin", &before);
        if let Err(error) = verify_endpoint_routes(&self.endpoints) {
            self.diagnostics
                .record("udp_rebind_error", &format!("code={}", error.code()));
            return Err(error);
        }
        match rebind_userspace_udp(&ifname, &self.rebind_peers) {
            Ok(()) => {
                let after = self.diagnostic_snapshot().replace('\n', " ");
                self.diagnostics.record("udp_rebind_ok", &after);
                Ok(ServiceTunnelState::Running)
            }
            Err(error) => {
                self.diagnostics
                    .record("udp_rebind_error", &format!("code={}", error.code()));
                Err(error)
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
struct DnsSnapshot {
    services: Vec<ServiceDns>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intent: Option<DnsIntent>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
struct DnsIntent {
    token: [u8; 16],
    servers: Vec<IpAddr>,
}

impl DnsIntent {
    fn new(servers: &[IpAddr]) -> Result<Self, ServiceError> {
        let mut token = [0; 16];
        if unsafe { libc::getentropy(token.as_mut_ptr().cast(), token.len()) } != 0 {
            return Err(backend_error("dns_receipt_entropy_unavailable"));
        }
        Ok(Self {
            token,
            servers: servers.to_vec(),
        })
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
struct ServiceDns {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
    // SystemConfiguration strings can contain IPv6 zone identifiers. Preserve
    // their spelling for the compare-and-restore transaction and its journal.
    servers: Vec<String>,
    search_domains: Vec<String>,
}

#[cfg(test)]
fn snapshot_dns() -> Result<DnsSnapshot, ServiceError> {
    let mut services = dns::snapshot().map_err(backend_error)?;
    for service in &mut services {
        let search_output = run_networksetup(&["-getsearchdomains", &service.name])?;
        service.search_domains = parse_search_domains(&search_output.stdout);
    }
    Ok(DnsSnapshot {
        services,
        intent: None,
    })
}

fn restore_dns_snapshot(snapshot: &DnsSnapshot) -> Result<(), ServiceError> {
    // Old snapshots recorded intent without proof of a committed write. They
    // can be discarded, but cannot authorize changing system preferences.
    if let Some(intent) = &snapshot.intent {
        dns::restore(&snapshot.services, intent).map_err(backend_error)?;
    }
    Ok(())
}

#[cfg(test)]
fn restore_qa_dns_baseline(snapshot: &DnsSnapshot) -> Result<(), ServiceError> {
    let mut first_error = None;
    for service in &snapshot.services {
        if let Err(error) = dns::set_test_servers(
            service.id.as_deref().expect("QA service ID"),
            &service.servers,
        ) {
            first_error.get_or_insert_with(|| backend_error(error));
        }
        if let Err(error) = set_network_values(
            "-setsearchdomains",
            &service.name,
            service.search_domains.iter().cloned(),
        ) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

#[cfg(test)]
fn set_network_values(
    command: &str,
    service: &str,
    values: impl Iterator<Item = String>,
) -> Result<(), ServiceError> {
    let mut args = vec![command.to_string(), service.to_string()];
    args.extend(values);
    if args.len() == 2 {
        args.push("Empty".to_string());
    }
    run_networksetup_owned(&args).map(|_| ())
}

#[cfg(test)]
fn parse_search_domains(output: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(output)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("There aren't any"))
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
fn run_networksetup(args: &[&str]) -> Result<Output, ServiceError> {
    let args: Vec<String> = args.iter().map(|value| (*value).to_string()).collect();
    run_networksetup_owned(&args)
}

#[cfg(test)]
fn run_networksetup_owned(args: &[String]) -> Result<Output, ServiceError> {
    let output = output_with_timeout(
        Command::new(NETWORKSETUP)
            .args(args)
            .env("LANG", "C")
            .env("LC_ALL", "C"),
        COMMAND_TIMEOUT,
    )
    .map_err(backend_error)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(ServiceError::Backend(
            "network_configuration_failed".to_string(),
        ))
    }
}

fn launch_userspace_tunnel(
    runtime_directory: &Path,
    receipt: &macos_launch::LaunchReceipt,
    utun: &utun::Utun,
    listener: &launch_listener::LaunchListener,
) -> Result<utun::GuardedEngine, ServiceError> {
    let state_file = runtime_directory.join(INTERFACE_STATE_FILE);
    remove_regular_file_if_present(&state_file).map_err(backend_error)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&state_file)
        .map_err(backend_error)?;
    writeln!(file, "{}", utun.name()).map_err(backend_error)?;
    file.sync_all().map_err(backend_error)?;
    let mut command = userspace_tunnel_command(&receipt.executable, &state_file, runtime_directory);
    command.env(macos_launch::NONCE_ENV, &receipt.launch_nonce);
    utun.launch(command, &listener.socket)
        .map_err(backend_error)
}

fn userspace_tunnel_command(
    executable: &Path,
    state_file: &Path,
    runtime_directory: &Path,
) -> Command {
    let mut command = Command::new(executable);
    command
        .arg("utun")
        .env("WG_TUN_NAME_FILE", state_file)
        .env_remove("WG_PROCESS_FOREGROUND")
        .stdin(Stdio::null());
    if let Some((stdout, stderr)) = userspace_log_streams(runtime_directory) {
        command
            .env("LOG_LEVEL", "error")
            .stdout(stdout)
            .stderr(stderr);
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    command
}

fn read_interface_name(path: &Path) -> Result<String, ServiceError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(backend_error)?;
    let meta = file.metadata().map_err(backend_error)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o022 != 0
        || meta.len() > 64
    {
        return Err(backend_error("invalid_interface_name"));
    }
    let mut value = String::new();
    file.take(65)
        .read_to_string(&mut value)
        .map_err(backend_error)?;
    if value.len() > 64 {
        return Err(backend_error("invalid_interface_name"));
    }
    let value = value.trim();
    let suffix = value
        .strip_prefix("utun")
        .ok_or_else(|| ServiceError::Backend("invalid_interface_name".to_string()))?;
    if suffix.is_empty() || suffix.len() > 10 || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ServiceError::Backend("invalid_interface_name".to_string()));
    }
    Ok(value.to_string())
}

fn prepare_legacy_owner(
    owner: &mut MemberOwner,
    mode: ResourceMode,
    directory: &Path,
    boot: &str,
    wireguard_go: &Path,
    amneziawg_go: &Path,
) -> Result<(), ServiceError> {
    owner
        .retire_starting_after_boot(boot)
        .map_err(backend_error)?;
    if let Some(receipt) = owner.receipt() {
        let proof =
            macos_launch::prove(directory, receipt, mode.owns_network()).map_err(backend_error)?;
        let captured = owner.capture_proven(proof, true);
        if owner.identity().is_none() {
            captured.map_err(backend_error)?;
        }
    }
    if owner.has_record() {
        return Ok(());
    }
    let state_file = directory.join(INTERFACE_STATE_FILE);
    match fs::symlink_metadata(&state_file) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(backend_error(error)),
        Ok(metadata)
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 =>
        {
            return Err(backend_error("userspace_state_untrusted"))
        }
        Ok(_) => (),
    }
    if !mode.owns_network() {
        return Err(backend_error("slot_recovery_requires_owner"));
    }
    let name = read_interface_name(&state_file)?;
    if kernel_ifindex(&name).map_err(backend_error)? == 0
        && matches!(fs::symlink_metadata(userspace_socket_path(&name)), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return remove_regular_file_if_present(&state_file).map_err(backend_error);
    }
    for (binary, transport) in [
        (wireguard_go, MemberTransport::WireGuard),
        (amneziawg_go, MemberTransport::AmneziaWg3),
    ] {
        if let Ok(proof) = macos_launch::prove_ordinary_legacy(directory, boot, binary, transport) {
            return owner.capture_ordinary_legacy(proof).map_err(backend_error);
        }
    }
    Err(backend_error("ordinary_userspace_ownership_unconfirmed"))
}

pub(crate) fn boot_identity() -> Result<String, ServiceError> {
    let mut bytes = [0u8; 128];
    let mut len = bytes.len();
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || len == 0 || len > bytes.len() {
        return Err(ServiceError::Backend("boot_identity_unavailable".into()));
    }
    let value = std::str::from_utf8(&bytes[..len])
        .map_err(backend_error)?
        .trim_end_matches('\0');
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(ServiceError::Backend("boot_identity_unavailable".into()));
    }
    Ok(value.to_owned())
}
pub(super) fn capture_member(name: &str, boot: &str) -> std::io::Result<UserspaceIdentity> {
    let index = kernel_ifindex(name)?;
    if index == 0 {
        return Err(std::io::Error::other("member_interface_unavailable"));
    }
    Ok(UserspaceIdentity {
        boot: boot.into(),
        interface: name.into(),
        index,
        socket: super::redundancy::capture_userspace_member(name)
            .map_err(|_| std::io::Error::other("slot_socket_identity_unavailable"))?,
    })
}
fn inspect_member(
    saved: &UserspaceIdentity,
    boot: &str,
) -> std::io::Result<Option<UserspaceIdentity>> {
    if kernel_ifindex(&saved.interface)? != saved.index {
        // The interface is gone. The published listener can remain on disk and
        // is still covered by the recorded identity for Stop.
        return Ok(None);
    }
    capture_member(&saved.interface, boot).map(Some)
}

fn kernel_ifindex(name: &str) -> std::io::Result<u32> {
    let name = std::ffi::CString::new(name).map_err(std::io::Error::other)?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index != 0 {
        return Ok(index);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENXIO) {
        return Ok(0);
    }
    Err(error)
}

fn inspect_member_for_stop(
    saved: &UserspaceIdentity,
) -> std::io::Result<Option<UserspaceIdentity>> {
    let index = kernel_ifindex(&saved.interface)?;
    if index != 0 && index != saved.index {
        return Ok(None);
    }
    let socket = launch_listener::observed(&userspace_socket_path(&saved.interface))?;
    if socket == Some(saved.socket) {
        return Ok(Some(saved.clone()));
    }
    if index == saved.index {
        wait_for_interface_exit(&saved.interface, saved.index)?;
    }
    Ok(None)
}

fn stop_member(owned: &UserspaceIdentity) -> std::io::Result<()> {
    unlink_member_socket(&owned.interface, owned.index, owned.socket)?;
    wait_for_interface_exit(&owned.interface, owned.index)
}

fn unlink_member_socket(
    name: &str,
    index: u32,
    socket: super::redundancy::SocketIdentity,
) -> std::io::Result<()> {
    let path = userspace_socket_path(name);
    if kernel_ifindex(name)? == index {
        launch_listener::unlink_if_owned(&path, socket)
    } else {
        launch_listener::retire_public(name, index, socket, ListenerOwner::Legacy)
    }
}

fn wait_for_interface_exit(name: &str, index: u32) -> std::io::Result<()> {
    let deadline = Instant::now() + START_TIMEOUT;
    while kernel_ifindex(name)? == index {
        if Instant::now() >= deadline {
            return Err(std::io::Error::other("userspace_cleanup_pending"));
        }
        thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}

fn validate_root_owned_binary(path: &Path) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(backend_error)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ServiceError::Backend("untrusted_wireguard_go".to_string()));
    }
    Ok(())
}

fn validate_runtime_directory(path: &Path) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(backend_error)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ServiceError::Backend(
            "untrusted_runtime_directory".to_string(),
        ));
    }
    Ok(())
}

fn load_dns_snapshot(path: &Path) -> Result<Option<DnsSnapshot>, ServiceError> {
    if !path.exists() {
        return Ok(None);
    }
    validate_state_file(path, "untrusted_dns_state")?;
    let file = fs::File::open(path).map_err(backend_error)?;
    serde_json::from_reader(file)
        .map(Some)
        .map_err(backend_error)
}

fn save_endpoints(path: &Path, endpoints: &[SocketAddr]) -> Result<(), ServiceError> {
    save_json_state(path, endpoints)
}

fn load_endpoints(path: &Path) -> Result<Vec<SocketAddr>, ServiceError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    validate_state_file(path, "untrusted_endpoint_state")?;
    let file = fs::File::open(path).map_err(backend_error)?;
    serde_json::from_reader(file).map_err(backend_error)
}

fn save_json_state<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<(), ServiceError> {
    let temporary = path.with_extension("tmp");
    remove_regular_file_if_present(&temporary).map_err(backend_error)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(backend_error)?;
    serde_json::to_writer(&mut file, value).map_err(backend_error)?;
    file.flush().map_err(backend_error)?;
    file.sync_all().map_err(backend_error)?;
    fs::rename(&temporary, path).map_err(backend_error)
}

fn validate_state_file(path: &Path, error_code: &str) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(backend_error)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ServiceError::Backend(error_code.to_string()));
    }
    Ok(())
}

fn remove_regular_file_if_present(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)
        }
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing to remove a non-regular state path",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn backend_error(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn receiptless_dns_snapshots_can_be_retired_without_system_preferences_access() {
        // A snapshot from the compare-by-address format could have been
        // written by a Start that exited before committing any DNS changes.
        let snapshot: DnsSnapshot = serde_json::from_value(serde_json::json!({
            "services": [],
            "applied_servers": ["198.18.247.18"]
        }))
        .unwrap();
        restore_dns_snapshot(&snapshot).unwrap();
    }

    #[test]
    fn search_domain_parser_ignores_the_empty_state_message() {
        assert_eq!(
            parse_search_domains(b"corp.example\nlab.example\n"),
            ["corp.example", "lab.example"]
        );
        assert!(
            parse_search_domains(b"There aren't any Search Domains set on Wi-Fi.\n").is_empty()
        );
    }

    #[test]
    fn userspace_tunnel_receives_no_configuration_or_key_arguments() {
        let runtime = tempfile::tempdir().expect("create runtime directory");
        let command = userspace_tunnel_command(
            Path::new("/Library/PrivilegedHelperTools/wireguard-go"),
            Path::new("/var/run/nelomai/interface-name"),
            runtime.path(),
        );
        let args: Vec<&OsStr> = command.get_args().collect();

        assert_eq!(args, [OsStr::new("utun")]);
        assert!(command
            .get_envs()
            .any(|(key, value)| key == "WG_TUN_NAME_FILE"
                && value == Some(OsStr::new("/var/run/nelomai/interface-name"))));
    }
}

#[cfg(test)]
#[test]
#[ignore = "requires the disposable macOS VM and root-owned userspace engines"]
fn native_ordinary_userspace_owner() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let model = Command::new("/usr/sbin/sysctl")
        .args(["-n", "hw.model"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&model.stdout).contains("VirtualMac"));
    let root = PathBuf::from(std::env::var_os("NELOMAI_OWNER_QA_ROOT").unwrap());
    let wg = PathBuf::from(std::env::var_os("NELOMAI_OWNER_QA_WG").unwrap());
    let awg = PathBuf::from(std::env::var_os("NELOMAI_OWNER_QA_AWG").unwrap());
    let stage = std::env::var("NELOMAI_OWNER_QA_STAGE").unwrap();
    let dns_writer = root.join("qa-dns-writer.json");
    let dns_ready = root.join("qa-dns-ready");
    if stage == "dns-writer" {
        let (replacement, applied): (ServiceDns, Vec<IpAddr>) =
            serde_json::from_slice(&fs::read(dns_writer).unwrap()).unwrap();
        dns::update_after_holding_lock(&[replacement], &applied, &dns_ready).unwrap();
        return;
    }
    let open = || MacosBackend::new(&wg, &awg, &root).unwrap();
    let witness = root.join("qa-listener");
    if matches!(
        stage.as_str(),
        "staged-crash"
            | "published-crash"
            | "handoff-crash"
            | "handoff-detaching"
            | "handoff-proof-failed"
    ) {
        let mut backend = open();
        let utun = utun::Utun::open().unwrap();
        let mut receipt = macos_launch::new_receipt(MemberTransport::WireGuard, &wg).unwrap();
        receipt.managed = Some(ManagedUtun {
            name: utun.name().to_owned(),
            index: utun.ifindex(),
            socket: None,
        });
        backend.transport_owner.begin(receipt.clone()).unwrap();
        let listener = launch_listener::LaunchListener::bind(&receipt).unwrap();
        let mut guardian = None;
        let socket_path = if stage != "staged-crash" {
            backend
                .transport_owner
                .record_managed_listener(listener.identity)
                .unwrap();
            listener.publish().unwrap();
            if stage.starts_with("handoff-") {
                guardian =
                    Some(launch_userspace_tunnel(&root, &receipt, &utun, &listener).unwrap());
            }
            userspace_socket_path(utun.name())
        } else {
            userspace_socket_path(utun.name())
                .parent()
                .unwrap()
                .join(".nelomai-launch")
                .join(&receipt.launch_nonce)
        };
        fs::write(&witness, socket_path.as_os_str().as_encoded_bytes()).unwrap();
        assert!(launch_listener::observed(&socket_path).unwrap().is_some());
        if stage == "handoff-proof-failed" {
            fs::remove_file(root.join(INTERFACE_STATE_FILE)).unwrap();
            backend.custody = Some(UtunCustody {
                engine: guardian.unwrap(),
                utun,
                socket: listener.identity,
            });
            drop(listener);
            assert!(backend.transport_owner.interrupted_launch());
            assert_eq!(backend.stop().unwrap(), ServiceTunnelState::Stopped);
            assert!(!socket_path.exists());
            assert!(!backend.transport_owner.cleanup_pending());
            return;
        }
        if stage == "handoff-detaching" {
            drop(listener);
            drop(backend);
            drop(guardian);
            let mut reopened = open();
            assert!(reopened.transport_owner.interrupted_launch());
            assert_eq!(reopened.status().unwrap(), ServiceTunnelState::Stopping);
            let detach = thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                drop(utun);
            });
            assert_eq!(reopened.stop().unwrap(), ServiceTunnelState::Stopped);
            detach.join().unwrap();
            assert!(!socket_path.exists());
            assert!(!reopened.transport_owner.cleanup_pending());
            return;
        }
        std::process::exit(79);
    }
    if matches!(stage.as_str(), "recover-launch" | "recover-reused-launch") {
        let path = PathBuf::from(fs::read_to_string(&witness).unwrap());
        let before = launch_listener::observed(&path).unwrap().unwrap();
        let mut backend = open();
        assert_eq!(backend.stop().unwrap(), ServiceTunnelState::Stopped);
        if stage == "recover-reused-launch" {
            assert_eq!(launch_listener::observed(&path).unwrap(), Some(before));
        } else {
            assert!(!path.exists());
        }
        assert!(!backend.transport_owner.cleanup_pending());
        return;
    }
    if stage == "recover" {
        let mut backend = open();
        assert!(backend.api.is_none());
        assert_eq!(backend.status().unwrap(), ServiceTunnelState::Stopping);
        assert!(backend.transport_owner.identity().is_some());
        let owned = backend.transport_owner.identity().unwrap().clone();
        assert_eq!(backend.stop().unwrap(), ServiceTunnelState::Stopped);
        assert!(!backend.ordinary_routes.as_ref().unwrap().has_resources());
        assert!(inspect_member(&owned, &boot_identity().unwrap())
            .unwrap()
            .is_none());
        assert!(backend.dns_snapshot.is_none());
        assert!(!backend.transport_owner.cleanup_pending());
        return;
    }
    if stage == "foreign" || stage == "legacy" {
        let launch_directory = if stage == "legacy" {
            root.clone()
        } else {
            root.join("other-owner")
        };
        if stage == "foreign" {
            fs::create_dir(&launch_directory).unwrap();
        }
        // This is the exact pre-receipt launch environment.
        let mut command = userspace_tunnel_command(
            &wg,
            &launch_directory.join(INTERFACE_STATE_FILE),
            &launch_directory,
        );
        assert!(
            crate::process::status_with_timeout(&mut command, COMMAND_TIMEOUT)
                .unwrap()
                .success()
        );
        let path = launch_directory.join(INTERFACE_STATE_FILE);
        let name = read_interface_name(&path).unwrap();
        let live = capture_member(&name, &boot_identity().unwrap()).unwrap();
        if stage == "foreign" {
            fs::write(root.join(INTERFACE_STATE_FILE), &name).unwrap();
        }
        let mut backend = open();
        if stage == "foreign" {
            assert!(backend.api.is_none());
            assert!(backend.stop().is_err());
            assert_eq!(
                inspect_member(&live, &boot_identity().unwrap())
                    .unwrap()
                    .as_ref(),
                Some(&live)
            );
            super::redundancy::remove_userspace_member(&name, live.index, live.socket).unwrap();
        } else {
            assert_eq!(backend.transport_owner.identity(), Some(&live));
            assert!(backend.transport_owner.stopping());
            backend.stop().unwrap();
        }
        return;
    }
    assert!(matches!(
        stage.as_str(),
        "live"
            | "crash"
            | "gone"
            | "orphan"
            | "occupied"
            | "foreign-reused"
            | "listener-changed"
            | "dns-foreign"
            | "probe-path"
    ));
    struct OccupiedSocket {
        path: PathBuf,
        identity: super::redundancy::SocketIdentity,
    }
    impl Drop for OccupiedSocket {
        fn drop(&mut self) {
            let _ = super::redundancy::unlink_socket_identity(&self.path, 0, self.identity);
        }
    }
    let occupied = (stage == "occupied").then(|| {
        let utun = launch_listener::open_available_utun().unwrap();
        let path = userspace_socket_path(utun.name());
        let socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let identity = launch_listener::observed(&path).unwrap().unwrap();
        let fixture = OccupiedSocket { path, identity };
        drop(socket);
        let index = utun.ifindex();
        let name = utun.name().to_owned();
        assert_eq!(
            utun::reserve_name(&name).unwrap_err().raw_os_error(),
            Some(libc::EBUSY)
        );
        assert_eq!(
            launch_listener::observed(&fixture.path).unwrap(),
            Some(fixture.identity)
        );
        drop(utun);
        let deadline = Instant::now() + START_TIMEOUT;
        while kernel_ifindex(&name).unwrap() == index {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        let reservation = loop {
            match utun::reserve_name(&name) {
                Ok(reservation) => break reservation,
                Err(error)
                    if error.raw_os_error() == Some(libc::EBUSY) && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("could not reserve the detached utun: {error}"),
            }
        };
        assert_eq!(kernel_ifindex(&name).unwrap(), 0);
        let other = utun::Utun::open().unwrap();
        assert_ne!(other.name(), name);
        drop(other);
        drop(reservation);
        fixture
    });
    let mut backend = open();
    let mut profile = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.123.236.7/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 198.19.236.0/24\nEndpoint = 198.51.100.194:51820\n".to_owned();
    struct RestoreDns(Option<DnsSnapshot>);
    impl Drop for RestoreDns {
        fn drop(&mut self) {
            if let Some(snapshot) = &self.0 {
                let _ = restore_qa_dns_baseline(snapshot);
            }
        }
    }
    let dns_baseline = (stage == "dns-foreign").then(|| {
        profile = profile.replace("[Peer]", "DNS = 198.18.247.18\n[Peer]");
        RestoreDns(Some(snapshot_dns().unwrap()))
    });
    let use_awg = std::env::var_os("NELOMAI_OWNER_QA_AWG_PROFILE").is_some();
    if use_awg {
        profile = profile.replace("[Peer]", "Jc = 5\nJmin = 48\nJmax = 192\nS1 = 132\nS2 = 67\nS3 = 28\nS4 = 30\nH1 = 100-120\nH2 = 121\nH3 = 122\nH4 = 123\nHeaderProtectionKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nContentPaddingAddition = 0-32\n\n[Peer]");
    }
    let configuration = crate::parse_configuration(&profile).unwrap();
    assert_eq!(
        configuration.transport == TunnelTransport::AmneziaWg3,
        use_awg
    );
    backend
        .start(&configuration, &DesktopTunnelOptions::default())
        .unwrap();
    assert_eq!(backend.status().unwrap(), ServiceTunnelState::Running);
    if let Some(mut baseline) = dns_baseline {
        let saved = baseline.0.as_ref().unwrap();
        let service = &saved.services[0].name;
        let dns = |name: &str| {
            dns::snapshot()
                .unwrap()
                .into_iter()
                .find(|service| service.name == name)
                .unwrap()
                .servers
        };
        let desired = configuration
            .dns
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(dns(service), desired);
        let foreign_dns = "fe80::2%en0";
        set_network_values(
            "-setsearchdomains",
            service,
            ["foreign.example".into()].into_iter(),
        )
        .unwrap();
        let mut replacement = backend
            .dns_snapshot
            .as_ref()
            .unwrap()
            .services
            .iter()
            .find(|current| current.name == *service)
            .unwrap()
            .clone();
        replacement.servers = vec![foreign_dns.into()];
        fs::write(
            dns_writer,
            serde_json::to_vec(&(replacement, &configuration.dns)).unwrap(),
        )
        .unwrap();
        let mut writer = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::macos::native_ordinary_userspace_owner",
                "--ignored",
            ])
            .env("NELOMAI_OWNER_QA_STAGE", "dns-writer")
            .spawn()
            .unwrap();
        let deadline = Instant::now() + START_TIMEOUT;
        while !dns_ready.exists() {
            assert!(Instant::now() < deadline && writer.try_wait().unwrap().is_none());
            thread::sleep(Duration::from_millis(10));
        }
        drop(backend);
        backend = open();
        assert!(writer.wait().unwrap().success());
        assert_eq!(backend.stop().unwrap(), ServiceTunnelState::Stopped);
        assert_eq!(dns(service), [foreign_dns]);
        assert_eq!(
            parse_search_domains(
                &run_networksetup(&["-getsearchdomains", service])
                    .unwrap()
                    .stdout
            ),
            ["foreign.example"]
        );
        for other in &saved.services[1..] {
            assert_eq!(dns(&other.name), other.servers);
        }
        let stale = dns::snapshot().unwrap();
        let newer = "192.0.2.54";
        set_network_values("-setdnsservers", service, [newer.to_string()].into_iter()).unwrap();
        let intent = DnsIntent::new(&configuration.dns).unwrap();
        assert!(dns::apply(&stale, &intent).is_err());
        assert_eq!(dns(service), [newer]);
        let mut other_location = dns::snapshot().unwrap();
        other_location.clear();
        assert!(dns::apply(&other_location, &intent).is_err());
        assert_eq!(dns(service), [newer]);
        let mut missing_service = dns::snapshot().unwrap();
        let mut removed = missing_service[0].clone();
        removed.id = Some("removed QA service".into());
        missing_service.push(removed);
        assert!(dns::apply(&missing_service, &intent).is_err());
        assert_eq!(dns(service), [newer]);

        // Another writer chooses the desired value after the baseline was
        // captured. A rejected Apply grants no ownership to either cleanup path.
        for restart in [false, true] {
            set_network_values("-setdnsservers", service, [newer.to_string()].into_iter()).unwrap();
            backend.capture_dns(&configuration.dns).unwrap();
            set_network_values(
                "-setdnsservers",
                service,
                configuration.dns.iter().map(ToString::to_string),
            )
            .unwrap();
            assert!(backend.apply_dns().is_err());
            if restart {
                drop(backend);
                backend = open();
            }
            assert_eq!(backend.stop().unwrap(), ServiceTunnelState::Stopped);
            assert_eq!(dns(service), desired);
            assert!(!root.join(DNS_STATE_FILE).exists());
        }

        // An interrupted Stop already committed its rollback. A subsequent
        // external change to the same value must survive recovery of Apply.
        set_network_values("-setdnsservers", service, [newer.to_string()].into_iter()).unwrap();
        backend.capture_dns(&configuration.dns).unwrap();
        backend.apply_dns().unwrap();
        let captured = backend.dns_snapshot.as_ref().unwrap();
        assert!(dns::commit_restore_before_restart(
            &captured.services,
            captured.intent.as_ref().unwrap()
        )
        .unwrap());
        assert_eq!(dns(service), [newer]);
        set_network_values(
            "-setdnsservers",
            service,
            configuration.dns.iter().map(ToString::to_string),
        )
        .unwrap();
        drop(backend);
        backend = open();
        assert_eq!(backend.stop().unwrap(), ServiceTunnelState::Stopped);
        assert_eq!(dns(service), desired);
        assert!(!root.join(DNS_STATE_FILE).exists());

        let scoped_baseline = "fe80::1%en0";
        dns::set_test_servers(
            saved.services[0].id.as_deref().unwrap(),
            &[scoped_baseline.into()],
        )
        .unwrap();
        assert_eq!(dns(service), [scoped_baseline]);
        backend
            .start(&configuration, &DesktopTunnelOptions::default())
            .unwrap();
        assert_eq!(dns(service), desired);
        let renamed = format!("Nelomai QA {}", std::process::id());
        run_networksetup(&["-renamenetworkservice", service, &renamed]).unwrap();
        let stopped = backend.stop();
        let after_rename = dns::snapshot();
        run_networksetup(&["-renamenetworkservice", &renamed, service]).unwrap();
        stopped.unwrap();
        let renamed_service = after_rename
            .unwrap()
            .into_iter()
            .find(|service| service.name == renamed)
            .unwrap();
        assert_eq!(renamed_service.servers, [scoped_baseline]);
        restore_qa_dns_baseline(saved).unwrap();
        baseline.0 = None;
        return;
    }
    if stage == "probe-path" {
        use crate::{Request, TunnelRequestHandler};
        let mut handler = TunnelRequestHandler::new(backend, "test");
        assert!(handler
            .handle(Request::metrics(false))
            .macos_probe_path
            .is_none());
        let before = handler
            .handle(Request::metrics(true))
            .macos_probe_path
            .unwrap();
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        socket
            .send_to(b"native ip counter test", "198.19.236.7:9")
            .unwrap();
        let limit = Instant::now() + Duration::from_secs(2);
        let after = loop {
            let current = handler
                .handle(Request::metrics(true))
                .macos_probe_path
                .unwrap();
            if current.sent_ip_packets > before.sent_ip_packets || Instant::now() >= limit {
                break current;
            }
            thread::sleep(Duration::from_millis(20));
        };
        let stop = handler.handle(Request::stop());
        assert_eq!(stop.state, Some(ServiceTunnelState::Stopped));
        assert!(handler
            .handle(Request::metrics(true))
            .macos_probe_path
            .is_none());
        assert!(before.same_tunnel(&after));
        assert!(after.sent_ip_packets > before.sent_ip_packets);
        assert_eq!(after.received_ip_packets, before.received_ip_packets);
        return;
    }
    if stage == "listener-changed" {
        let owned = backend.verified_identity().unwrap();
        let daemon = backend.transport_owner.managed_process().unwrap();
        let previous = super::redundancy::SocketIdentity {
            inode: owned.socket.inode + 1,
            ..owned.socket
        };
        let error = launch_listener::retire_public(
            &owned.interface,
            owned.index,
            previous,
            ListenerOwner::Verified(daemon),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "userspace_cleanup_pending");
        assert_eq!(backend.status().unwrap(), ServiceTunnelState::Running);
    }
    if let Some(occupied) = &occupied {
        assert_ne!(
            userspace_socket_path(&backend.verified_identity().unwrap().interface),
            occupied.path
        );
    }
    if stage == "crash" {
        std::process::exit(79);
    }
    if stage == "foreign-reused" {
        let owned = backend.verified_identity().unwrap().clone();
        drop(backend);
        let deadline = Instant::now() + START_TIMEOUT;
        let foreign = loop {
            let utun = utun::Utun::open().unwrap();
            if utun.name() == owned.interface {
                break utun;
            }
            drop(utun);
            assert!(
                Instant::now() < deadline,
                "kernel did not release the original name"
            );
            thread::sleep(Duration::from_millis(25));
        };
        assert_eq!(foreign.ifindex(), owned.index);
        assert!(Command::new("/sbin/ifconfig")
            .args([foreign.name(), "inet", "198.18.247.4", "198.18.247.4", "up"])
            .status()
            .unwrap()
            .success());
        NativeMacCommands
            .run(
                "/sbin/route",
                &[
                    "-n".into(),
                    "add".into(),
                    "-dst".into(),
                    "198.19.236.0".into(),
                    "-netmask".into(),
                    "255.255.255.0".into(),
                    "-interface".into(),
                    owned.interface.clone(),
                ],
            )
            .unwrap();
        let path = userspace_socket_path(&owned.interface);
        assert_eq!(
            launch_listener::observed(&path).unwrap(),
            Some(owned.socket)
        );
        backend = open();
        assert_eq!(backend.stop().unwrap(), ServiceTunnelState::Stopped);
        assert!(!backend.ordinary_routes.as_ref().unwrap().has_resources());
        let route = NativeMacCommands
            .run(
                "/sbin/route",
                &["-n".into(), "get".into(), "198.19.236.12".into()],
            )
            .unwrap();
        assert!(route
            .lines()
            .any(|line| line.trim().strip_prefix("interface: ") == Some(foreign.name())));
        assert_eq!(
            launch_listener::observed(&path).unwrap(),
            Some(owned.socket)
        );
        drop(foreign);
        let deadline = Instant::now() + START_TIMEOUT;
        let reservation = loop {
            match utun::reserve_name(&owned.interface) {
                Ok(reservation) => break reservation,
                Err(error)
                    if error.raw_os_error() == Some(libc::EBUSY) && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("foreign owner did not release the unit: {error}"),
            }
        };
        drop(reservation);
        let fresh = launch_listener::open_available_utun().unwrap();
        assert_eq!(fresh.name(), owned.interface);
        assert!(!path.exists());
        return;
    }
    if matches!(stage.as_str(), "gone" | "orphan") {
        let live = backend.verified_identity().unwrap().clone();
        drop(backend);
        let socket = userspace_socket_path(&live.interface);
        if stage == "orphan" {
            let held = root.join("qa-orphan");
            fs::rename(&socket, &held).unwrap();
            wait_for_interface_exit(&live.interface, live.index).unwrap();
            // Model a daemon that exited without unlinking the public name.
            fs::rename(&held, &socket).unwrap();
        } else {
            super::redundancy::remove_userspace_member(&live.interface, live.index, live.socket)
                .unwrap();
        }
        backend = open();
        assert!(backend.api.is_none());
        assert_eq!(backend.status().unwrap(), ServiceTunnelState::Stopping);
        assert!(backend.dns_snapshot.is_none());
        assert!(!backend.ordinary_routes.as_ref().unwrap().has_resources());
    }
    backend.stop().unwrap();
    assert_eq!(backend.status().unwrap(), ServiceTunnelState::Stopped);
    assert!(!backend.transport_owner.cleanup_pending());
    if let Some(occupied) = &occupied {
        assert_eq!(
            launch_listener::observed(&occupied.path).unwrap(),
            Some(occupied.identity)
        );
    }
}

fn verify_nat_binding(binding: &(String, u32), name: &str, index: u32) -> std::io::Result<()> {
    if index == 0 || binding.0 != name || binding.1 != index {
        return Err(std::io::Error::other("vm_nat_interface_changed"));
    }
    Ok(())
}
#[cfg(test)]
mod forward_nat_binding_tests {
    use super::verify_nat_binding;
    #[test]
    fn reused_utun_name_cannot_authorize_nat_on_another_incarnation() {
        let binding = ("utun4".to_string(), 20);
        assert!(verify_nat_binding(&binding, "utun4", 20).is_ok());
        assert!(verify_nat_binding(&binding, "utun4", 21).is_err());
        assert!(verify_nat_binding(&binding, "utun5", 20).is_err());
        assert!(verify_nat_binding(&binding, "utun4", 0).is_err());
    }
}
