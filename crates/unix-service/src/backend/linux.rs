use super::linux_owner::{LinuxIdentity, LinuxOwner, MemberTransport, NativeProof};
use super::redundancy::ResourceMode;
use super::{
    append_userspace_log, apply_and_verify_awg3_configuration, build_backend_configuration,
    configure_interface_after_awg3, host_diagnostic_snapshot, rebind_peers_for_start,
    rebind_peers_from_host, rebind_userspace_udp, state_name, transport_name,
    userspace_log_streams, userspace_socket_path, DiagnosticJournal, RebindPeer,
};
use crate::process::{status_with_timeout, COMMAND_TIMEOUT};
use crate::routes::{LinuxOrdinaryRoutes, RouteManager, SystemRouteBackend};
use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use defguard_wireguard_rs::{host::Host, Kernel, Userspace, WGApi, WireguardInterfaceApi};
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_client_tunnel::{DesktopTunnelOptions, TunnelMetrics, TunnelTransport};
use nelomai_contracts::dispatcher::TunnelSlot;
use std::cell::RefCell;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

mod ordinary_link;
use ordinary_link::OrdinaryLinkStore;

const START_TIMEOUT: Duration = Duration::from_secs(3);

pub struct LinuxBackend {
    mode: ResourceMode,
    forward_nat: crate::forward_nat::Owner<
        crate::forward_nat::linux::Adapter<crate::forward_nat::NativeCommands>,
    >,
    nat_refresh_at: Option<Instant>,
    nat_unavailable: bool,
    nat_interface: Option<(String, u32)>,
    member_owner: Option<LinuxOwner>,
    member_receive: RefCell<Option<crate::member_network::counters::ReceiveCounter>>,
    wireguard_api: WGApi<Kernel>,
    amneziawg_api: WGApi<Userspace>,
    amneziawg_go: PathBuf,
    runtime_directory: PathBuf,
    active_transport: Option<TunnelTransport>,
    rebind_peers: Vec<RebindPeer>,
    ordinary_routes: LinuxOrdinaryRoutes,
    ordinary_link: Option<OrdinaryLinkStore>,
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
        let mut ordinary_routes = LinuxOrdinaryRoutes::new(&runtime_directory)?;
        let mut routes = RouteManager::new(&runtime_directory, SystemRouteBackend::new()?)?;
        let forward_nat = crate::forward_nat::Owner::open(
            &runtime_directory,
            &boot_identity()?,
            0,
            crate::forward_nat::linux::Adapter::new(crate::forward_nat::NativeCommands::default()),
        )
        .map_err(backend_error)?;
        // A reserved name alone cannot establish ownership after a restart.
        let ordinary_link = if mode.owns_network() {
            Some(OrdinaryLinkStore::open(&runtime_directory)?)
        } else {
            None
        };
        let saved = ordinary_link.as_ref().and_then(OrdinaryLinkStore::owned);
        let ordinary_pending = ordinary_link
            .as_ref()
            .is_some_and(OrdinaryLinkStore::cleanup_pending);
        let active_transport = saved.map(|link| link.transport());
        if mode.owns_network() && active_transport.is_none() && !ordinary_pending {
            ordinary_routes.cleanup()?;
            routes.cleanup()?;
        }
        let state = if forward_nat.is_recovering()
            || member_owner
                .as_ref()
                .is_some_and(LinuxOwner::cleanup_pending)
            || ordinary_pending
        {
            ServiceTunnelState::Stopping
        } else if active_transport.is_some() {
            ServiceTunnelState::Running
        } else {
            ServiceTunnelState::Stopped
        };
        let rebind_peers = if active_transport == Some(TunnelTransport::AmneziaWg3) {
            amneziawg_api
                .read_interface_data()
                .ok()
                .as_ref()
                .map(rebind_peers_from_host)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
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
            forward_nat,
            nat_refresh_at: None,
            nat_unavailable: false,
            nat_interface: None,
            member_owner,
            member_receive: RefCell::new(None),
            wireguard_api,
            amneziawg_api,
            amneziawg_go,
            runtime_directory,
            active_transport,
            rebind_peers,
            ordinary_routes,
            ordinary_link,
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
        if self.forward_nat.has_resources()
            || self.active_transport.is_some()
            || self
                .ordinary_link
                .as_ref()
                .is_some_and(OrdinaryLinkStore::cleanup_pending)
            || self.ordinary_routes.has_routes()
            || self.routes.has_routes()
        {
            self.stop_inner()?;
        }

        let mut native = build_backend_configuration(configuration)?;
        let interface_name = self.mode.linux_interface(configuration.transport);
        native.interface.name = interface_name.to_string();
        if !self.mode.owns_network() {
            native.interface.port = 0;
        }

        let boot = boot_identity()?;
        let transport = match configuration.transport {
            TunnelTransport::WireGuard => MemberTransport::WireGuard,
            TunnelTransport::AmneziaWg3 => MemberTransport::AmneziaWg3,
        };
        let launch = |group| {
            launch_member_native(
                &self.amneziawg_go,
                &self.runtime_directory,
                interface_name,
                transport,
                &boot,
                group,
            )
        };
        if let Some(owner) = &mut self.member_owner {
            owner
                .launch(transport, &boot, launch)
                .map_err(backend_error)?;
        } else {
            self.ordinary_link
                .as_mut()
                .ok_or(ServiceError::InvalidRequest)?
                .launch(
                    &self.amneziawg_go,
                    &self.runtime_directory,
                    transport,
                    &boot,
                )?;
        }
        self.active_transport = Some(configuration.transport);
        let configured_interface_index = kernel_interface_index(interface_name)?;
        if configured_interface_index == 0
            || (self.member_owner.is_some()
                && self.member_interface_index()? != configured_interface_index)
        {
            return Err(backend_error("owned_vpn_interface_changed"));
        }
        if let Some(store) = &self.ordinary_link {
            store.verify(configured_interface_index)?;
        }
        self.nat_interface = Some((interface_name.into(), configured_interface_index));

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

        if configuration.transport == TunnelTransport::AmneziaWg3 {
            // The TUN starts down. Set addrgenmode before UP so the kernel
            // cannot create a second link-local prefix used by physical LANs.
            for args in [&["addrgenmode", "none"][..], &["up"][..]] {
                let status = status_with_timeout(
                    Command::new(ip_command().map_err(backend_error)?)
                        .args(["link", "set", "dev", interface_name])
                        .args(args)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null()),
                    COMMAND_TIMEOUT,
                )
                .map_err(backend_error)?;
                if !status.success()
                    || kernel_interface_index(interface_name)? != configured_interface_index
                {
                    return Err(backend_error("interface_up_failed"));
                }
            }
        }
        let configured_routes: Result<(), ServiceError> = if !self.mode.owns_network() {
            self.member_interface_index().and_then(|index| {
                super::member_rpf::enable_member_reply_path(interface_name, index)
                    .map_err(backend_error)
            })
        } else {
            let store = self
                .ordinary_link
                .as_mut()
                .ok_or(ServiceError::InvalidRequest)?;
            store.verify(configured_interface_index)?;
            self.ordinary_routes.apply(
                configured_interface_index,
                interface_name,
                &native.interface.peers,
                options,
            )?;
            if !configuration.dns.is_empty() {
                store.verify(configured_interface_index)?;
                store
                    .owned_mut()
                    .ok_or(ServiceError::InvalidRequest)?
                    .dns_entry = Some(resolvconf_entry(interface_name));
                store.persist()?;
            }
            match configuration.transport {
                TunnelTransport::WireGuard => {
                    self.wireguard_api.configure_dns(&configuration.dns, &[])
                }
                TunnelTransport::AmneziaWg3 => {
                    self.amneziawg_api.configure_dns(&configuration.dns, &[])
                }
            }
            .map_err(backend_error)
        };
        if let Err(error) = configured_routes {
            let _ = self.stop_inner();
            return Err(error);
        }
        if kernel_interface_index(interface_name)? != configured_interface_index
            || (self.member_owner.is_some()
                && self.member_interface_index()? != configured_interface_index)
        {
            return Err(backend_error("owned_vpn_interface_changed"));
        }
        super::forward_nat_reply::enable_owned_reply_path(
            interface_name,
            configured_interface_index,
        )
        .map_err(backend_error)?;
        self.refresh_forward_nat()?;
        if let Some(store) = self.ordinary_link.as_mut() {
            store.owned_mut().ok_or(ServiceError::InvalidRequest)?.ready = true;
            store.persist()?;
        }
        self.rebind_peers = rebind_peers_for_start(configuration, self.mode);
        Ok(())
    }

    fn refresh_forward_nat(&mut self) -> Result<(), ServiceError> {
        let Some(transport) = self.active_transport else {
            return Ok(());
        };
        let Some((name, index)) = self.nat_interface.clone() else {
            return Ok(());
        };
        if self.mode.linux_interface(transport) != name || kernel_interface_index(&name)? != index {
            return Err(backend_error("vm_nat_interface_changed"));
        }
        self.read_active_interface()?;
        if self.member_owner.is_some() && self.member_interface_index()? != index {
            return Err(backend_error("vm_nat_interface_changed"));
        }
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
        // Monitoring never grants cleanup authority and must not pin the link.
        self.member_receive.get_mut().take();
        if let Some(owner) = &mut self.member_owner {
            let boot = boot_identity()?;
            owner
                .stop_owned(&boot, inspect_member, remove_member)
                .map_err(backend_error)?;
            self.active_transport = None;
            self.rebind_peers.clear();
            return Ok(());
        }
        if let Some(store) = self.ordinary_link.as_mut() {
            store.stop()?;
        }
        self.active_transport = None;
        self.rebind_peers.clear();
        self.ordinary_routes.cleanup()?;
        self.routes.cleanup()
    }

    fn read_active_interface(&self) -> Result<Host, ServiceError> {
        if let Some(store) = &self.ordinary_link {
            store.verify_active()?;
        }
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
            self.ordinary_link
                .as_ref()
                .and_then(OrdinaryLinkStore::owned)
                .is_some_and(|r| r.ready)
                || self.routes.has_routes(),
            self.active_transport == Some(TunnelTransport::AmneziaWg3) && self.mode.owns_network()
                || self.ordinary_routes.has_routes(),
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

// Match the resolver entry used by defguard on systems with Debian resolvconf.
fn resolvconf_entry(interface: &str) -> String {
    let executable = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|p| p.join("resolvconf"))
            .find(|p| p.is_file())
    });
    if executable
        .and_then(|p| std::fs::symlink_metadata(p).ok())
        .is_some_and(|m| m.is_file())
    {
        if let Ok(order) = std::fs::read_to_string("/etc/resolvconf/interface-order") {
            if let Some(prefix) = order
                .lines()
                .filter_map(|l| l.trim().strip_suffix('*'))
                .find(|s| {
                    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return format!("{prefix}.{interface}");
            }
        }
    }
    interface.into()
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
    group: u32,
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
            // fails on collisions and installs IFLA_GROUP in the SAME RTM_NEWLINK
            // request as exclusive creation; never mark an existing link.
            let status = status_with_timeout(
                &mut super::linux_owner::kernel_create_command(ip_command()?, interface, group)?,
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
            group: kernel_interface_group(interface)?,
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

fn kernel_interface_group(interface: &str) -> std::io::Result<u32> {
    std::fs::read_to_string(
        Path::new("/sys/class/net")
            .join(interface)
            .join("netdev_group"),
    )?
    .trim_end_matches('\n')
    .parse()
    .map_err(|_| std::io::Error::other("slot_interface_group_invalid"))
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
        self.forward_nat.is_recovering()
            || self
                .member_owner
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
    fn member_data_counters(
        &self,
    ) -> Result<crate::member_network::counters::DataCounters, ServiceError> {
        // The unretained trait fallback cannot exclude WG control RX on Linux.
        // Retain this monitor only behind the original member ownership proof.
        use crate::member_network::counters::{read_owned, ReceiveCounter};
        let index = self.member_interface_index()?;
        read_owned(
            index,
            || self.member_interface_index().map_err(std::io::Error::other),
            |index| {
                let mut receive = self
                    .member_receive
                    .try_borrow_mut()
                    .map_err(|_| std::io::Error::other("member_counter_busy"))?;
                if receive.is_none() {
                    *receive = Some(ReceiveCounter::open(index)?);
                }
                receive
                    .as_mut()
                    .expect("initialized receive counter")
                    .read(index)
            },
        )
        .map_err(|_| ServiceError::Backend("member_counters_unavailable".into()))
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
        if self.forward_nat.is_recovering() {
            return Ok(ServiceTunnelState::Stopping);
        }
        if self
            .ordinary_link
            .as_ref()
            .is_some_and(OrdinaryLinkStore::cleanup_pending)
        {
            return Ok(ServiceTunnelState::Stopping);
        }
        if self.member_cleanup_pending() && self.active_transport.is_none() {
            return Ok(ServiceTunnelState::Stopping);
        }
        if self.active_transport.is_some() && self.read_active_interface().is_ok() {
            Ok(ServiceTunnelState::Running)
        } else if self.active_transport.is_none()
            && self.state == ServiceTunnelState::Stopped
            && !self.ordinary_routes.has_routes()
            && !self.routes.has_routes()
        {
            Ok(ServiceTunnelState::Stopped)
        } else {
            Ok(ServiceTunnelState::Failed)
        }
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
    let mut command = amneziawg_command(executable, interface_name, runtime_directory);
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

fn amneziawg_command(executable: &Path, interface_name: &str, runtime_directory: &Path) -> Command {
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
    command
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
