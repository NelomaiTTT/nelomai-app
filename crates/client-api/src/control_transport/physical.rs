use std::{
    io,
    net::{IpAddr, SocketAddr},
};

#[cfg(unix)]
#[path = "unix_command.rs"]
mod command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Interface {
    pub index: u32,
    pub name: String,
    pub identity: String,
    pub addresses: Vec<IpAddr>,
    pub gateway: Option<IpAddr>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DnsServer {
    pub address: SocketAddr,
    pub interface: Interface,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub ipv4: Option<Interface>,
    pub ipv6: Option<Interface>,
}

impl Snapshot {
    pub fn interface(&self, address: IpAddr) -> io::Result<&Interface> {
        if address.is_ipv4() {
            self.ipv4.as_ref()
        } else {
            self.ipv6.as_ref()
        }
        .ok_or_else(|| io::Error::other("physical_egress_unavailable"))
    }
}

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod native;
#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod native;
#[cfg(windows)]
#[path = "windows.rs"]
mod native;

pub(super) fn snapshot() -> io::Result<Snapshot> {
    native::snapshot()
}
#[cfg(not(target_os = "linux"))]
pub(super) fn resolve(host: &str, snapshot: &Snapshot) -> io::Result<Vec<IpAddr>> {
    native::resolve(host, snapshot)
}
#[cfg(target_os = "linux")]
pub(super) fn dns_servers(snapshot: &Snapshot) -> io::Result<Vec<DnsServer>> {
    native::dns_servers(snapshot)
}
pub(super) fn bind_socket(
    socket: &socket2::Socket,
    interface: &Interface,
    remote: SocketAddr,
) -> io::Result<()> {
    native::bind_socket(socket, interface, remote)
}

#[cfg(all(test, target_os = "macos"))]
#[path = "linux.rs"]
#[allow(dead_code)]
mod linux_fixture_tests;
#[cfg(all(test, not(windows)))]
#[path = "windows_policy.rs"]
mod windows_policy_tests;
