use super::ProbeDatagram;
use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
};

/// No unbound fallback: interface binding failure aborts before connect/send.
/// Interface index and source must come from the helper's owned member, not IPC.
pub struct NativeProbeSocket(UdpSocket);

impl NativeProbeSocket {
    pub fn open(index: u32, source: Ipv4Addr, target: Ipv4Addr) -> io::Result<Self> {
        if index == 0
            || source.is_unspecified()
            || source.is_multicast()
            || source.is_loopback()
            || target.is_unspecified()
            || target.is_multicast()
            || target.is_loopback()
            || target.is_broadcast()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let socket = UdpSocket::bind(SocketAddrV4::new(source, 0))?;
        bind_interface(&socket, index)?;
        socket.set_nonblocking(true)?;
        socket.connect(SocketAddrV4::new(target, 53))?;
        Ok(Self(socket))
    }
}

impl ProbeDatagram for NativeProbeSocket {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.0.send(packet)
    }
    fn receive(&mut self, packet: &mut [u8]) -> io::Result<usize> {
        self.0.recv(packet)
    }
}

#[cfg(target_os = "macos")]
fn bind_interface(socket: &UdpSocket, index: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let status = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            (&index as *const u32).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_interface(socket: &UdpSocket, index: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) };
    let status = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.to_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn bind_interface(socket: &UdpSocket, index: u32) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, WSAGetLastError, IPPROTO_IP, IP_UNICAST_IF, SOCKET_ERROR,
    };
    // WinSock's IPv4 IP_UNICAST_IF takes the interface index in network order.
    let index = index.to_be();
    let status = unsafe {
        setsockopt(
            socket.as_raw_socket() as _,
            IPPROTO_IP,
            IP_UNICAST_IF,
            (&index as *const u32).cast(),
            std::mem::size_of::<u32>() as i32,
        )
    };
    if status == SOCKET_ERROR {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn bind_interface(_: &UdpSocket, _: u32) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}
