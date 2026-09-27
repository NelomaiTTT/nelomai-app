use super::linux_owner::{LinuxIdentity, LinuxOwner, MemberTransport, NativeProof};
use super::redundancy::ResourceMode;
use super::{
    append_userspace_log, apply_and_verify_awg3_configuration, build_backend_configuration,
    configure_interface_after_awg3, host_diagnostic_snapshot, rebind_peers_for_start,
    rebind_peers_from_host, rebind_userspace_udp, state_name, transport_name,
    userspace_log_streams, userspace_socket_path, DiagnosticJournal, RebindPeer,
};
use crate::process::{status_with_timeout, COMMAND_TIMEOUT};
use crate::routes::{LinuxUserspaceRouteManager, RouteManager, SystemRouteBackend, AWG_FWMARK};
use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use defguard_wireguard_rs::{host::Host, Kernel, Userspace, WGApi, WireguardInterfaceApi};
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_client_tunnel::{DesktopTunnelOptions, TunnelMetrics, TunnelTransport};
use nelomai_contracts::dispatcher::TunnelSlot;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const START_TIMEOUT: Duration = Duration::from_secs(3);

pub struct LinuxBackend {
    mode: ResourceMode,
    member_owner: Option<LinuxOwner>,
    wireguard_api: WGApi<Kernel>,
    amneziawg_api: WGApi<Userspace>,
    amneziawg_go: PathBuf,
    runtime_directory: PathBuf,
    active_transport: Option<TunnelTransport>,
    rebind_peers: Vec<RebindPeer>,
    amneziawg_routes: LinuxUserspaceRouteManager,
    routes: RouteManager<SystemRouteBackend>,
    state: ServiceTunnelState,
    diagnostics: DiagnosticJournal,
}

impl LinuxBackend {
    pub fn new(
        amneziawg_go: impl Into<PathBuf>,
        runtime_directory: impl AsRef<Path>,
    ) -> Result<Self, ServiceError> {
        Self::with_mode(
            amneziawg_go.into(),
            runtime_directory.as_ref(),
            ResourceMode::Single,
            None,
        )
    }

    /// Called only by the session owner after establishing its private directory
    /// and endpoint bypasses. This backend never owns common routes or DNS.
    pub fn new_member(
        amneziawg_go: impl Into<PathBuf>,
        runtime_directory: &Path,
        slot: TunnelSlot,
        scope: SessionScope,
    ) -> Result<Self, ServiceError> {
        let owner = LinuxOwner::open_root(
            &ResourceMode::Member(slot).runtime_path(runtime_directory),
            scope,
            slot,
        )
        .map_err(backend_error)?;
        Self::with_mode(
            amneziawg_go.into(),
            runtime_directory,
            ResourceMode::Member(slot),
            Some(owner),
        )
    }

    fn with_mode(
        amneziawg_go: PathBuf,
        root: &Path,
        mode: ResourceMode,
        member_owner: Option<LinuxOwner>,
    ) -> Result<Self, ServiceError> {
        let runtime_directory = mode.runtime_path(root);
        let wireguard_api = WGApi::<Kernel>::new(mode.linux_interface(TunnelTransport::WireGuard))
            .map_err(backend_error)?;
        let amneziawg_api =
            WGApi::<Userspace>::new(mode.linux_interface(TunnelTransport::AmneziaWg3))
                .map_err(backend_error)?;
        let mut amneziawg_routes = LinuxUserspaceRouteManager::new(&runtime_directory)?;
        let mut routes = RouteManager::new(&runtime_directory, SystemRouteBackend::new()?)?;
        // Reopened members expose cleanup only. Never adopt or configure a
        // resource by name, and never reconstruct a running session from disk.
        let wireguard_host = if mode.owns_network() {
            wireguard_api.read_interface_data().ok()
        } else {
            None
        };
        let amneziawg_host = if mode.owns_network() {
            amneziawg_api.read_interface_data().ok()
        } else {
            None
        };
        let wireguard_running = wireguard_host.is_some();
        let amneziawg_running = amneziawg_host.is_some();
        if wireguard_running && amneziawg_running {
            return Err(ServiceError::Backend(
                "multiple_tunnel_interfaces_detected".to_string(),
            ));
        }
        let active_transport = if wireguard_running {
            Some(TunnelTransport::WireGuard)
        } else if amneziawg_running {
            Some(TunnelTransport::AmneziaWg3)
        } else {
            if mode.owns_network() {
                amneziawg_routes.cleanup()?;
                routes.cleanup()?;
            }
            None
        };
        let state = if member_owner
            .as_ref()
            .is_some_and(LinuxOwner::cleanup_pending)
        {
            ServiceTunnelState::Stopping
        } else if active_transport.is_some() {
            ServiceTunnelState::Running
        } else {
            ServiceTunnelState::Stopped
        };
        let rebind_peers = amneziawg_host
            .as_ref()
            .map(rebind_peers_from_host)
            .unwrap_or_default();
        let mut diagnostics = DiagnosticJournal::persistent(&runtime_directory);
        diagnostics.record(
            "helper_initialized",
            &format!(
                "state={} transport={}",
                state_name(state),
                transport_name(active_transport)
            ),
        );
        Ok(Self {
            mode,
            member_owner,
            wireguard_api,
            amneziawg_api,
            amneziawg_go,
            runtime_directory,
            active_transport,
            rebind_peers,
            amneziawg_routes,
            routes,
            state,
            diagnostics,
        })
    }

    fn start_inner(
        &mut self,
        configuration: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<(), ServiceError> {
        if self.active_transport.is_some()
            || self.amneziawg_routes.has_routes()
            || self.routes.has_routes()
        {
            self.stop_inner()?;
        }

        let mut native = build_backend_configuration(configuration)?;
        let interface_name = self.mode.linux_interface(configuration.transport);
        native.interface.name = interface_name.to_string();
        if self.mode.owns_network() && configuration.transport == TunnelTransport::AmneziaWg3 {
            native.interface.fwmark = Some(AWG_FWMARK);
        }
        if self.mode.owns_network() {
            self.routes.apply(options)?;
        }
        if !self.mode.owns_network() {
            native.interface.port = 0;
        }

        if let Some(owner) = &mut self.member_owner {
            let boot = boot_identity()?;
            let transport = match configuration.transport {
                TunnelTransport::WireGuard => MemberTransport::WireGuard,
                TunnelTransport::AmneziaWg3 => MemberTransport::AmneziaWg3,
            };
            owner
                .launch(transport, &boot, |alias| {
                    launch_member_native(
                        &self.amneziawg_go,
                        &self.runtime_directory,
                        interface_name,
                        transport,
                        &boot,
                        alias,
                    )
                })
                .map_err(backend_error)?;
        } else {
            match configuration.transport {
                TunnelTransport::WireGuard => {
                    self.wireguard_api
                        .create_interface()
                        .map_err(backend_error)?;
                }
                TunnelTransport::AmneziaWg3 => {
                    validate_root_owned_binary(&self.amneziawg_go)?;
                    launch_amneziawg_go(
                        &self.amneziawg_go,
                        interface_name,
                        &self.runtime_directory,
                    )?;
                }
            }
        }
        self.active_transport = Some(configuration.transport);
        if self.member_owner.is_some() {
            self.member_interface_index()?;
        }

        let configured = configure_interface_after_awg3(
            configuration.awg3.as_ref(),
            |parameters| apply_and_verify_awg3_configuration(interface_name, parameters),
            || {
                match configuration.transport {
                    TunnelTransport::WireGuard => {
                        self.wireguard_api.configure_interface(&native.interface)
                    }
                    TunnelTransport::AmneziaWg3 => {
                        self.amneziawg_api.configure_interface(&native.interface)
                    }
                }
                .map_err(backend_error)
            },
        );
        native.interface.prvkey.zeroize();
        if let Err(error) = configured {
            let _ = self.stop_inner();
            return Err(error);
        }

        let configured_routes: Result<(), ServiceError> = if !self.mode.owns_network() {
            self.member_interface_index().and_then(|index| {
                super::member_rpf::enable_member_reply_path(interface_name, index)
                    .map_err(backend_error)
            })
        } else {
            match configuration.transport {
                TunnelTransport::WireGuard => self
                    .wireguard_api
                    .configure_peer_routing(&native.interface.peers)
                    .and_then(|_| self.wireguard_api.configure_dns(&configuration.dns, &[]))
                    .map_err(backend_error),
                TunnelTransport::AmneziaWg3 => self
                    .amneziawg_routes
                    .apply(interface_name, &native.interface.peers)
                    .and_then(|_| {
                        self.amneziawg_api
                            .configure_dns(&configuration.dns, &[])
                            .map_err(backend_error)
                    }),
            }
        };
        if let Err(error) = configured_routes {
            let _ = self.stop_inner();
            return Err(error);
        }
        self.rebind_peers = rebind_peers_for_start(configuration, self.mode);
        Ok(())
    }

    fn stop_inner(&mut self) -> Result<(), ServiceError> {
        if let Some(owner) = &mut self.member_owner {
            let boot = boot_identity()?;
            owner
                .stop_owned(&boot, inspect_member, remove_member)
                .map_err(backend_error)?;
            self.active_transport = None;
            self.rebind_peers.clear();
            return Ok(());
        }
        let transport = if self.mode.owns_network() {
            self.active_transport.take()
        } else {
            self.active_transport
        };
        let mut first_error = None;
        if let Err(error) = if self.mode.owns_network() {
            self.amneziawg_routes.cleanup()
        } else {
            Ok(())
        } {
            first_error.get_or_insert(error);
        }
        let interface_result = match transport {
            Some(TunnelTransport::WireGuard) => {
                self.wireguard_api.remove_interface().map_err(backend_error)
            }
            Some(TunnelTransport::AmneziaWg3) => {
                self.amneziawg_api.remove_interface().map_err(backend_error)
            }
            None => Ok(()),
        };
        if let Err(error) = interface_result {
            first_error.get_or_insert(error);
        } else {
            self.active_transport = None;
            self.rebind_peers.clear();
        }
        if let Err(error) = if self.mode.owns_network() {
            self.routes.cleanup()
        } else {
            Ok(())
        } {
            first_error.get_or_insert(error);
        }
        first_error.map_or(Ok(()), Err)
    }

    fn read_active_interface(&self) -> Result<Host, ServiceError> {
        if self.member_owner.is_some() {
            self.member_interface_index()?;
        }
        match self.active_transport {
            Some(TunnelTransport::WireGuard) => self
                .wireguard_api
                .read_interface_data()
                .map_err(backend_error),
            Some(TunnelTransport::AmneziaWg3) => self
                .amneziawg_api
                .read_interface_data()
                .map_err(backend_error),
            None => Err(ServiceError::Backend("tunnel_not_running".to_string())),
        }
    }

    fn diagnostic_snapshot(&self) -> String {
        let mut snapshot = format!(
            "state={}\ntransport={}\nroutes_active={}\nawg_routes_active={}",
            state_name(self.state),
            transport_name(self.active_transport),
            self.routes.has_routes(),
            self.amneziawg_routes.has_routes(),
        );
        match self.read_active_interface() {
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

fn kernel_interface_index(interface: &str) -> Result<u32, ServiceError> {
    let name = std::ffi::CString::new(interface).map_err(|_| ServiceError::InvalidRequest)?;
    Ok(unsafe { libc::if_nametoindex(name.as_ptr()) })
}

pub(crate) fn boot_identity() -> Result<String, ServiceError> {
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(backend_error)?;
    let boot = boot.trim();
    if boot.len() != 36
        || !boot.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(backend_error("boot_identity_unavailable"));
    }
    Ok(boot.into())
}

fn ip_command() -> std::io::Result<&'static str> {
    ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"]
        .into_iter()
        .find(|p| {
            std::fs::symlink_metadata(p).is_ok_and(|metadata| {
                super::linux_owner::trusted_ip_file(
                    metadata.is_file(),
                    metadata.uid(),
                    metadata.mode(),
                )
            })
        })
        .ok_or_else(|| std::io::Error::other("ip_command_unavailable"))
}

fn launch_member_native(
    executable: &Path,
    runtime: &Path,
    interface: &str,
    transport: MemberTransport,
    boot: &str,
    alias: &str,
) -> std::io::Result<LinuxIdentity> {
    use std::io::{Error, ErrorKind};
    if boot_identity().map_err(Error::other)? != boot
        || kernel_interface_index(interface).map_err(Error::other)? != 0
    {
        return Err(Error::other("slot_interface_already_exists"));
    }
    // Reject stale sockets (including symlinks), rather than adopting them.
    match std::fs::symlink_metadata(userspace_socket_path(interface)) {
        Err(e) if e.kind() == ErrorKind::NotFound => (),
        Err(e) => return Err(e),
        Ok(_) => return Err(Error::other("slot_socket_already_exists")),
    }
    match transport {
        MemberTransport::WireGuard => {
            // The vendor's create_interface swallows EEXIST. `ip link add`
            // fails on collisions and installs the alias in the SAME RTM_NEWLINK
            // request as exclusive creation; never set an alias on an old link.
            let status = status_with_timeout(
                &mut super::linux_owner::kernel_create_command(ip_command()?, interface, alias),
                COMMAND_TIMEOUT,
            )?;
            if !status.success() {
                return Err(Error::other("slot_interface_create_failed"));
            }
        }
        MemberTransport::AmneziaWg3 => {
            validate_root_owned_binary(executable).map_err(Error::other)?;
            launch_amneziawg_go(executable, interface, runtime).map_err(Error::other)?;
        }
    }
    capture_member(interface, transport, boot)
}

fn capture_member(
    interface: &str,
    transport: MemberTransport,
    boot: &str,
) -> std::io::Result<LinuxIdentity> {
    use std::io::Error;
    if boot_identity().map_err(Error::other)? != boot {
        return Err(Error::other("slot_boot_changed"));
    }
    let index = kernel_interface_index(interface).map_err(Error::other)?;
    if index == 0 {
        return Err(Error::other("slot_interface_missing"));
    }
    let proof = match transport {
        MemberTransport::WireGuard => NativeProof::Kernel {
            alias: std::fs::read_to_string(
                Path::new("/sys/class/net").join(interface).join("ifalias"),
            )?
            .trim_end_matches('\n')
            .into(),
        },
        MemberTransport::AmneziaWg3 => NativeProof::Userspace(
            super::redundancy::capture_userspace_member(interface).map_err(Error::other)?,
        ),
    };
    if kernel_interface_index(interface).map_err(Error::other)? != index
        || boot_identity().map_err(Error::other)? != boot
    {
        return Err(Error::other("slot_interface_identity_changed"));
    }
    Ok(LinuxIdentity {
        boot: boot.into(),
        interface: interface.into(),
        index,
        proof,
    })
}

fn inspect_member(saved: &LinuxIdentity) -> std::io::Result<Option<LinuxIdentity>> {
    use std::io::{Error, ErrorKind};
    let boot = boot_identity().map_err(Error::other)?;
    if boot != saved.boot {
        return Err(Error::other("slot_boot_changed"));
    }
    let index = kernel_interface_index(&saved.interface).map_err(Error::other)?;
    let transport = match saved.proof {
        NativeProof::Kernel { .. } => {
            if index == 0 {
                return Ok(None);
            }
            MemberTransport::WireGuard
        }
        NativeProof::Userspace(_) => {
            // A missing socket alone can mean removal is still in progress.
            // Only absence of BOTH resources acknowledges cleanup.
            match std::fs::symlink_metadata(userspace_socket_path(&saved.interface)) {
                Err(e) if e.kind() == ErrorKind::NotFound && index == 0 => return Ok(None),
                Err(e) => return Err(e),
                Ok(_) => (),
            }
            MemberTransport::AmneziaWg3
        }
    };
    capture_member(&saved.interface, transport, &boot).map(Some)
}

fn verify_member(saved: &LinuxIdentity) -> std::io::Result<()> {
    if inspect_member(saved)?.as_ref() != Some(saved) {
        return Err(std::io::Error::other("slot_interface_identity_changed"));
    }
    Ok(())
}

fn remove_member(saved: &LinuxIdentity) -> std::io::Result<()> {
    verify_member(saved)?;
    match saved.proof {
        NativeProof::Kernel { .. } => super::redundancy::remove_kernel_member(
            &mut Some(saved.index),
            &mut NativeKernelMember { identity: saved },
        ),
        NativeProof::Userspace(socket) => {
            super::redundancy::remove_userspace_member(&saved.interface, socket)
        }
    }
    .map_err(std::io::Error::other)
}

struct NativeKernelMember<'a> {
    identity: &'a LinuxIdentity,
}
impl super::redundancy::KernelMemberControl for NativeKernelMember<'_> {
    fn index(&mut self) -> Result<u32, ServiceError> {
        match inspect_member(self.identity).map_err(backend_error)? {
            Some(actual) if actual == *self.identity => Ok(actual.index),
            None => Ok(0),
            _ => Err(backend_error("slot_interface_identity_changed")),
        }
    }
    fn delete(&mut self) -> Result<(), ServiceError> {
        verify_member(self.identity).map_err(backend_error)?;
        // Members never installed DNS/fwmark policy. The vendor combined
        // remove_interface() clears DNS after deleting the link and can fail
        // there, leaving retries unable to distinguish success from failure.
        let ip = ip_command().map_err(backend_error)?;
        let status = status_with_timeout(
            Command::new(ip)
                .args(["link", "delete", "dev", &self.identity.interface])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            COMMAND_TIMEOUT,
        )
        .map_err(backend_error)?;
        if status.success() {
            Ok(())
        } else {
            Err(ServiceError::Backend(
                "slot_interface_cleanup_failed".into(),
            ))
        }
    }
}

impl ServiceTunnelBackend for LinuxBackend {
    fn member_recovery_scope(&self) -> Option<SessionScope> {
        self.member_owner.as_ref().map(|owner| owner.scope.clone())
    }
    fn member_cleanup_pending(&self) -> bool {
        self.member_owner
            .as_ref()
            .is_some_and(LinuxOwner::cleanup_pending)
    }
    fn member_slot(&self) -> Option<TunnelSlot> {
        match self.mode {
            ResourceMode::Single => None,
            ResourceMode::Member(slot) => Some(slot),
        }
    }
    fn member_interface_index(&self) -> Result<u32, ServiceError> {
        if self.mode.owns_network() {
            return Err(ServiceError::Backend("member_interface_unavailable".into()));
        }
        let owner = self
            .member_owner
            .as_ref()
            .ok_or(ServiceError::InvalidRequest)?;
        if self.active_transport.is_none() || owner.stopping() {
            return Err(backend_error("member_not_running"));
        }
        let identity = owner
            .identity()
            .ok_or_else(|| backend_error("member_not_running"))?;
        let actual = inspect_member(identity)
            .map_err(backend_error)?
            .ok_or_else(|| backend_error("member_interface_unavailable"))?;
        owner.owned(&actual).map_err(backend_error)?;
        Ok(actual.index)
    }
    fn start(
        &mut self,
        configuration: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        // Reject before failure cleanup: duplicate Start must not stop a member.
        if let Some(owner) = &self.member_owner {
            owner.ensure_fresh().map_err(backend_error)?;
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
        if self.member_cleanup_pending() && self.active_transport.is_none() {
            return Ok(ServiceTunnelState::Stopping);
        }
        if self.active_transport.is_some() && self.read_active_interface().is_ok() {
            Ok(ServiceTunnelState::Running)
        } else if self.active_transport.is_none()
            && self.state == ServiceTunnelState::Stopped
            && !self.amneziawg_routes.has_routes()
            && !self.routes.has_routes()
        {
            Ok(ServiceTunnelState::Stopped)
        } else {
            Ok(ServiceTunnelState::Failed)
        }
    }

    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        self.routes.physical_network_fingerprint()
    }

    fn metrics(&self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
        let host = self.read_active_interface()?;
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

    fn diagnostics(&self) -> Result<String, ServiceError> {
        let mut output = self.diagnostics.render(&self.diagnostic_snapshot());
        append_userspace_log(&mut output, &self.runtime_directory);
        Ok(output)
    }

    fn rebind_udp(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        if self.member_owner.is_some() {
            self.member_interface_index()?;
        }
        if !self.mode.owns_network() && self.active_transport == Some(TunnelTransport::WireGuard) {
            let index = self.member_interface_index()?;
            super::kernel_rebind::reset_kernel_port(index).map_err(backend_error)?;
            if self.member_interface_index()? != index
                || self
                    .wireguard_api
                    .read_interface_data()
                    .map_err(backend_error)?
                    .listen_port
                    == 0
            {
                return Err(ServiceError::Backend(
                    "kernel_udp_rebind_unconfirmed".into(),
                ));
            }
            return Ok(ServiceTunnelState::Running);
        }
        if self.active_transport != Some(TunnelTransport::AmneziaWg3) {
            return Err(ServiceError::Backend("udp_rebind_unsupported".to_string()));
        }
        let before = self.diagnostic_snapshot().replace('\n', " ");
        self.diagnostics.record("udp_rebind_begin", &before);
        match rebind_userspace_udp(
            self.mode.linux_interface(TunnelTransport::AmneziaWg3),
            &self.rebind_peers,
        ) {
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

fn launch_amneziawg_go(
    executable: &Path,
    interface_name: &str,
    runtime_directory: &Path,
) -> Result<(), ServiceError> {
    let socket_path = userspace_socket_path(interface_name);
    if socket_path.exists() {
        return Err(ServiceError::Backend(
            "amneziawg_interface_already_exists".to_string(),
        ));
    }
    let mut command = Command::new(executable);
    command.arg(interface_name).stdin(Stdio::null());
    if let Some((stdout, stderr)) = userspace_log_streams(runtime_directory) {
        command
            .env("LOG_LEVEL", "error")
            .stdout(stdout)
            .stderr(stderr);
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let status = status_with_timeout(&mut command, COMMAND_TIMEOUT).map_err(backend_error)?;
    if !status.success() {
        return Err(ServiceError::Backend(
            "amneziawg_go_start_failed".to_string(),
        ));
    }
    let started = Instant::now();
    while started.elapsed() < START_TIMEOUT {
        if socket_path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(ServiceError::Backend(
        "amneziawg_go_start_timeout".to_string(),
    ))
}

fn validate_root_owned_binary(path: &Path) -> Result<(), ServiceError> {
    let metadata = std::fs::symlink_metadata(path).map_err(backend_error)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ServiceError::Backend("untrusted_amneziawg_go".to_string()));
    }
    Ok(())
}

fn backend_error(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Backend(error.to_string())
}
