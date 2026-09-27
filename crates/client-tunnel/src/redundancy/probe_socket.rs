use super::ProbeDatagram;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
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
        #[cfg(windows)]
        let socket = exclusive::open(index, source, target)?;
        #[cfg(not(windows))]
        let socket = {
            let socket = UdpSocket::bind(SocketAddrV4::new(source, 0))?;
            bind_interface(&socket, index)?;
            socket.set_nonblocking(true)?;
            socket.connect(SocketAddrV4::new(target, 53))?;
            socket
        };
        Ok(Self(socket))
    }

    /// Duplicate the handle to the SAME connected socket, without rebinding.
    /// The base can retain its exclusive Windows port between probe requests.
    /// Options and receive queue are shared: the enclosing owner must serialize
    /// probes and withdraw the WFP permit before releasing the base/last clone.
    pub fn try_clone(&self) -> io::Result<Self> {
        self.0.try_clone().map(Self)
    }

    /// The actual bound source address and ephemeral port for the exact permit.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
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

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn bind_interface(_: &UdpSocket, _: u32) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(any(windows, test))]
mod exclusive {
    use super::*;

    /// The returned socket owns its handle immediately, including on errors.
    trait SocketApi {
        type Socket;
        fn initialize(&mut self) -> io::Result<()>;
        fn create(&mut self) -> io::Result<Self::Socket>;
        fn exclusive(&mut self, socket: &Self::Socket) -> io::Result<()>;
        fn bind(&mut self, socket: &Self::Socket, source: SocketAddrV4) -> io::Result<()>;
        fn interface(&mut self, socket: &Self::Socket, network_order_index: u32) -> io::Result<()>;
        fn nonblocking(&mut self, socket: &Self::Socket) -> io::Result<()>;
        fn connect(&mut self, socket: &Self::Socket, target: SocketAddrV4) -> io::Result<()>;
    }

    fn construct<A: SocketApi>(
        api: &mut A,
        index: u32,
        source: Ipv4Addr,
        target: Ipv4Addr,
    ) -> io::Result<A::Socket> {
        api.initialize()?;
        let socket = api.create()?; // owns/RAII-closes even if any next step fails
        api.exclusive(&socket)?;
        api.bind(&socket, SocketAddrV4::new(source, 0))?;
        // WinSock IPv4 IP_UNICAST_IF takes a network-byte-order interface index.
        api.interface(&socket, index.to_be())?;
        api.nonblocking(&socket)?;
        api.connect(&socket, SocketAddrV4::new(target, 53))?;
        Ok(socket)
    }

    #[cfg(windows)]
    pub(super) fn open(index: u32, source: Ipv4Addr, target: Ipv4Addr) -> io::Result<UdpSocket> {
        construct(&mut native::WinSock, index, source, target)
    }

    #[cfg(windows)]
    mod native {
        use super::*;
        use std::{
            mem::size_of,
            os::windows::io::{AsRawSocket, FromRawSocket},
            ptr,
        };
        use windows_sys::Win32::Networking::WinSock::{
            bind, setsockopt, WSAGetLastError, WSASocketW, AF_INET, INVALID_SOCKET, IN_ADDR,
            IN_ADDR_0, IPPROTO_IP, IPPROTO_UDP, IP_UNICAST_IF, SOCKADDR_IN, SOCKET_ERROR,
            SOCK_DGRAM, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, WSA_FLAG_NO_HANDLE_INHERIT,
            WSA_FLAG_OVERLAPPED,
        };

        pub(super) struct WinSock;
        impl SocketApi for WinSock {
            type Socket = UdpSocket;

            fn initialize(&mut self) -> io::Result<()> {
                // Let std perform and retain its process-wide WSAStartup before
                // raw WSASocketW. Binding loopback sends no packets; this temporary
                // socket never connects/sends and never receives a WFP exemption.
                // Do not call WSACleanup: std owns the initialization lifetime.
                drop(UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?);
                Ok(())
            }

            fn create(&mut self) -> io::Result<UdpSocket> {
                let raw = unsafe {
                    WSASocketW(
                        AF_INET as i32,
                        SOCK_DGRAM,
                        IPPROTO_UDP,
                        ptr::null(),
                        0,
                        WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
                    )
                };
                if raw == INVALID_SOCKET {
                    return Err(last_error());
                }
                // Transfer sole ownership immediately, before any fallible setup.
                // UdpSocket::drop calls closesocket on every subsequent error.
                Ok(unsafe { UdpSocket::from_raw_socket(raw as _) })
            }

            fn exclusive(&mut self, socket: &UdpSocket) -> io::Result<()> {
                let enabled: i32 = 1;
                check(unsafe {
                    setsockopt(
                        socket.as_raw_socket() as _,
                        SOL_SOCKET,
                        SO_EXCLUSIVEADDRUSE,
                        (&enabled as *const i32).cast(),
                        size_of::<i32>() as i32,
                    )
                })
            }

            fn bind(&mut self, socket: &UdpSocket, source: SocketAddrV4) -> io::Result<()> {
                let address = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: source.port().to_be(),
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(source.ip().octets()),
                        },
                    },
                    sin_zero: [0; 8],
                };
                check(unsafe {
                    bind(
                        socket.as_raw_socket() as _,
                        (&address as *const SOCKADDR_IN).cast(),
                        size_of::<SOCKADDR_IN>() as i32,
                    )
                })
            }

            fn interface(
                &mut self,
                socket: &UdpSocket,
                network_order_index: u32,
            ) -> io::Result<()> {
                check(unsafe {
                    setsockopt(
                        socket.as_raw_socket() as _,
                        IPPROTO_IP,
                        IP_UNICAST_IF,
                        (&network_order_index as *const u32).cast(),
                        size_of::<u32>() as i32,
                    )
                })
            }

            fn nonblocking(&mut self, socket: &UdpSocket) -> io::Result<()> {
                socket.set_nonblocking(true)
            }
            fn connect(&mut self, socket: &UdpSocket, target: SocketAddrV4) -> io::Result<()> {
                socket.connect(target)
            }
        }

        fn last_error() -> io::Error {
            io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
        }
        fn check(status: i32) -> io::Result<()> {
            if status == SOCKET_ERROR {
                Err(last_error())
            } else {
                Ok(())
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{cell::RefCell, rc::Rc};

        #[derive(Clone, Debug, PartialEq, Eq)]
        enum Call {
            Initialize,
            Create,
            Exclusive,
            Bind(SocketAddrV4),
            Interface([u8; 4]),
            Nonblocking,
            Connect(SocketAddrV4),
            Close,
        }
        struct FakeSocket(Rc<RefCell<Vec<Call>>>);
        impl Drop for FakeSocket {
            fn drop(&mut self) {
                self.0.borrow_mut().push(Call::Close);
            }
        }
        struct FakeApi {
            calls: Rc<RefCell<Vec<Call>>>,
            fail_at: Option<usize>,
        }
        impl FakeApi {
            fn new(fail_at: Option<usize>) -> Self {
                Self {
                    calls: Rc::new(RefCell::new(vec![])),
                    fail_at,
                }
            }
            fn record(&mut self, call: Call) -> io::Result<()> {
                let mut calls = self.calls.borrow_mut();
                let index = calls.len();
                calls.push(call);
                if self.fail_at == Some(index) {
                    Err(io::Error::from_raw_os_error(10013))
                } else {
                    Ok(())
                }
            }
        }
        impl SocketApi for FakeApi {
            type Socket = FakeSocket;
            fn initialize(&mut self) -> io::Result<()> {
                self.record(Call::Initialize)
            }
            fn create(&mut self) -> io::Result<Self::Socket> {
                self.record(Call::Create)?;
                Ok(FakeSocket(self.calls.clone()))
            }
            fn exclusive(&mut self, _: &Self::Socket) -> io::Result<()> {
                self.record(Call::Exclusive)
            }
            fn bind(&mut self, _: &Self::Socket, source: SocketAddrV4) -> io::Result<()> {
                self.record(Call::Bind(source))
            }
            fn interface(&mut self, _: &Self::Socket, index: u32) -> io::Result<()> {
                self.record(Call::Interface(index.to_ne_bytes()))
            }
            fn nonblocking(&mut self, _: &Self::Socket) -> io::Result<()> {
                self.record(Call::Nonblocking)
            }
            fn connect(&mut self, _: &Self::Socket, target: SocketAddrV4) -> io::Result<()> {
                self.record(Call::Connect(target))
            }
        }
        fn source() -> Ipv4Addr {
            Ipv4Addr::new(10, 8, 0, 2)
        }
        fn target() -> Ipv4Addr {
            Ipv4Addr::new(9, 9, 9, 9)
        }
        fn expected() -> Vec<Call> {
            vec![
                Call::Initialize,
                Call::Create,
                Call::Exclusive,
                Call::Bind(SocketAddrV4::new(source(), 0)),
                Call::Interface([1, 2, 3, 4]),
                Call::Nonblocking,
                Call::Connect(SocketAddrV4::new(target(), 53)),
            ]
        }

        #[test]
        fn initializes_before_creation_and_exclusively_binds_before_connect() {
            let mut api = FakeApi::new(None);
            let socket = construct(&mut api, 0x01020304, source(), target()).unwrap();
            assert_eq!(*api.calls.borrow(), expected());
            drop(socket);
            let mut calls = expected();
            calls.push(Call::Close);
            assert_eq!(*api.calls.borrow(), calls);
        }

        #[test]
        fn every_failure_preserves_error_stops_construction_and_closes_once_if_owned() {
            for fail_at in 0..7 {
                let mut api = FakeApi::new(Some(fail_at));
                let result = construct(&mut api, 0x01020304, source(), target());
                assert_eq!(result.err().unwrap().raw_os_error(), Some(10013));
                let mut calls = expected()[..=fail_at].to_vec();
                if fail_at >= 2 {
                    calls.push(Call::Close);
                }
                assert_eq!(*api.calls.borrow(), calls, "failure at {fail_at}");
            }
        }
    }
}
