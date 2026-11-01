//! Scoped DNSServiceGetAddrInfo; the system resolver retains encryption policy.
use super::{verify_index, Interface, Snapshot};
use std::{
    ffi::CString,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
    time::{Duration, Instant},
};
const DEADLINE: Duration = Duration::from_secs(7);
const ADD: u32 = 2;
const MORE_COMING: u32 = 1;
const TIMEOUT_FLAG: u32 = 0x10000;
type ServiceRef = *mut libc::c_void;
type Reply = unsafe extern "C" fn(
    ServiceRef,
    u32,
    u32,
    i32,
    *const libc::c_char,
    *const libc::sockaddr,
    u32,
    *mut libc::c_void,
);
// DNS-SD symbols are exported by libSystem on macOS.
#[link(name = "System")]
extern "C" {
    fn DNSServiceGetAddrInfo(
        reference: *mut ServiceRef,
        flags: u32,
        index: u32,
        protocol: u32,
        hostname: *const libc::c_char,
        callback: Option<Reply>,
        context: *mut libc::c_void,
    ) -> i32;
    fn DNSServiceRefSockFD(reference: ServiceRef) -> i32;
    fn DNSServiceProcessResult(reference: ServiceRef) -> i32;
    fn DNSServiceRefDeallocate(reference: ServiceRef);
}
struct Query {
    host: CString,
    index: u32,
    ipv6: bool,
    protocol: u32,
}
impl Query {
    fn new(host: &str, snapshot: &Snapshot) -> io::Result<Self> {
        let (interface, ipv6) = selected(snapshot)?;
        let host = host.strip_suffix('.').unwrap_or(host);
        if interface.index == 0
            || host.is_empty()
            || host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    || label.starts_with('-')
                    || label.ends_with('-')
            })
        {
            return Err(invalid());
        }
        Ok(Self {
            host: CString::new(format!("{host}.")).map_err(|_| invalid())?,
            index: interface.index,
            ipv6,
            protocol: if ipv6 { 2 } else { 1 },
        })
    }
}
fn selected(snapshot: &Snapshot) -> io::Result<(&Interface, bool)> {
    match (&snapshot.ipv4, &snapshot.ipv6) {
        (Some(i), None) => Ok((i, false)),
        (None, Some(i)) => Ok((i, true)),
        _ => Err(invalid()),
    }
}
struct Answers {
    index: u32,
    ipv6: bool,
    deadline: Instant,
    addresses: Vec<IpAddr>,
    finished: bool,
}
impl Answers {
    fn accept(&mut self, index: u32, flags: u32, address: IpAddr) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(timed_out());
        }
        // Unicast records have InterfaceID=Any in the native daemon reply.
        // The nonzero request scope, rather than callback 0, selects DNS egress.
        if self.finished
            || (index != 0 && index != self.index)
            || address.is_ipv6() != self.ipv6
            || !valid_address(address)
        {
            return Err(invalid());
        }
        if flags & ADD != 0 {
            if !self.addresses.contains(&address) {
                if self.addresses.len() >= 64 {
                    return Err(invalid());
                }
                self.addresses.push(address);
            }
        } else {
            self.addresses.retain(|a| *a != address);
        }
        self.finished = flags & MORE_COMING == 0;
        Ok(())
    }
}
struct Operation {
    reference: ServiceRef,
    answers: Answers,
    error: Option<io::Error>,
    callbacks: usize,
}
impl Operation {
    fn close(&mut self) {
        let reference = std::mem::replace(&mut self.reference, ptr::null_mut());
        if !reference.is_null() {
            unsafe {
                DNSServiceRefDeallocate(reference);
            }
        }
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        self.close();
    }
}

pub(super) fn resolve(host: &str, snapshot: &Snapshot) -> io::Result<Vec<IpAddr>> {
    let deadline = Instant::now() + DEADLINE;
    let (interface, ipv6) = selected(snapshot)?;
    verify_index(interface)?;
    if let Ok(address) = host.parse::<IpAddr>() {
        if address.is_ipv6() != ipv6 || !valid_address(address) {
            return Err(invalid());
        }
        return Ok(vec![address]);
    }
    let query = Query::new(host, snapshot)?;
    let mut operation = Box::new(Operation {
        reference: ptr::null_mut(),
        answers: Answers {
            index: query.index,
            ipv6: query.ipv6,
            deadline,
            addresses: vec![],
            finished: false,
        },
        error: None,
        callbacks: 0,
    });
    let context = (&mut *operation as *mut Operation).cast();
    // The C daemon handshake itself has an upstream timeout of 60 seconds.
    // The enclosing async caller also bounds wait time and retained workers.
    let status = unsafe {
        DNSServiceGetAddrInfo(
            &mut operation.reference,
            TIMEOUT_FLAG,
            query.index,
            query.protocol,
            query.host.as_ptr(),
            Some(reply),
            context,
        )
    };
    if status != 0 {
        operation.reference = ptr::null_mut();
        return Err(native_error(status));
    }
    if operation.reference.is_null() {
        return Err(invalid());
    }
    let fd = unsafe { DNSServiceRefSockFD(operation.reference) };
    if fd < 0 {
        return Err(invalid());
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // Do not let a partial daemon message hold DNSServiceProcessResult beyond
    // the outer deadline. A truncated IPC message fails closed, never unscoped.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    while !operation.answers.finished && operation.error.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let status = unsafe {
            libc::poll(
                &mut poll,
                1,
                remaining.as_millis().min(i32::MAX as u128).max(1) as i32,
            )
        };
        if status < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if status == 0 {
            return Err(timed_out());
        }
        if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(invalid());
        }
        let status = unsafe { DNSServiceProcessResult(operation.reference) };
        if status != 0 {
            return Err(native_error(status));
        }
    }
    verify_index(interface)?;
    if let Some(error) = operation.error.take() {
        return Err(error);
    }
    if operation.answers.addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "physical_dns_no_addresses",
        ));
    }
    Ok(std::mem::take(&mut operation.answers.addresses))
}
unsafe extern "C" fn reply(
    _: ServiceRef,
    flags: u32,
    index: u32,
    error: i32,
    _: *const libc::c_char,
    address: *const libc::sockaddr,
    _: u32,
    context: *mut libc::c_void,
) {
    if context.is_null() {
        return;
    }
    let operation = unsafe { &mut *context.cast::<Operation>() };
    operation.callbacks += 1;
    let result = if error != 0 {
        Err(native_error(error))
    } else if operation.callbacks > 128 {
        Err(invalid())
    } else {
        unsafe { decode_address(address) }.and_then(|a| operation.answers.accept(index, flags, a))
    };
    if let Err(error) = result {
        operation.error = Some(error);
    }
    if operation.answers.finished || operation.error.is_some() {
        operation.close();
    }
}
unsafe fn decode_address(address: *const libc::sockaddr) -> io::Result<IpAddr> {
    if address.is_null() {
        return Err(invalid());
    }
    let header = unsafe { &*address };
    match i32::from(header.sa_family) {
        libc::AF_INET if usize::from(header.sa_len) >= std::mem::size_of::<libc::sockaddr_in>() => {
            let address = unsafe { ptr::read_unaligned(address.cast::<libc::sockaddr_in>()) };
            Ok(IpAddr::V4(Ipv4Addr::from(
                address.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6
            if usize::from(header.sa_len) >= std::mem::size_of::<libc::sockaddr_in6>() =>
        {
            let address = unsafe { ptr::read_unaligned(address.cast::<libc::sockaddr_in6>()) };
            Ok(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
        }
        _ => Err(invalid()),
    }
}
fn valid_address(a: IpAddr) -> bool {
    !a.is_unspecified()
        && !a.is_loopback()
        && !a.is_multicast()
        && a != IpAddr::V4(Ipv4Addr::BROADCAST)
        && !matches!(a,IpAddr::V6(v) if v.to_ipv4_mapped().is_some())
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "physical_dns_state_invalid")
}
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "physical_dns_timeout")
}
fn native_error(code: i32) -> io::Error {
    io::Error::new(
        if code == -65568 {
            io::ErrorKind::TimedOut
        } else {
            io::ErrorKind::Other
        },
        "physical_dns_native_query_failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn interface() -> Interface {
        Interface {
            index: 6,
            name: "en0".into(),
            identity: "physical-fixture".into(),
            addresses: vec!["192.0.2.4".parse().unwrap(), "2001:db8::4".parse().unwrap()],
            gateway: None,
        }
    }
    fn snapshot(ipv6: bool) -> Snapshot {
        Snapshot {
            ipv4: if ipv6 { None } else { Some(interface()) },
            ipv6: if ipv6 { Some(interface()) } else { None },
        }
    }
    fn answers(ipv6: bool) -> Answers {
        Answers {
            index: 6,
            ipv6,
            deadline: Instant::now() + Duration::from_secs(7),
            addresses: vec![],
            finished: false,
        }
    }
    #[test]
    fn native_request_is_fully_qualified_and_scoped_to_selected_family() {
        let query = Query::new("panel.example", &snapshot(false)).unwrap();
        assert_eq!((query.index, query.protocol), (6, 1));
        assert_eq!(query.host.to_bytes(), b"panel.example.");
        let query = Query::new("panel.example.", &snapshot(true)).unwrap();
        assert_eq!((query.index, query.protocol), (6, 2));
        let mut invalid = snapshot(false);
        invalid.ipv4.as_mut().unwrap().index = 0;
        assert!(Query::new("panel.example", &invalid).is_err());
        assert!(Query::new("bad..example", &snapshot(false)).is_err());
    }
    #[test]
    fn native_unicast_zero_index_is_allowed_but_foreign_scope_is_rejected() {
        let mut state = answers(false);
        state.accept(0, 2, "192.0.2.44".parse().unwrap()).unwrap();
        assert_eq!(
            state.addresses,
            vec!["192.0.2.44".parse::<IpAddr>().unwrap()]
        );
        assert!(state.finished);
        let mut state = answers(false);
        assert!(state.accept(9, 2, "192.0.2.44".parse().unwrap()).is_err());
        let mut state = answers(false);
        assert!(state.accept(6, 2, "2001:db8::44".parse().unwrap()).is_err());
        let mut state = answers(false);
        assert!(state.accept(6, 2, "127.0.0.1".parse().unwrap()).is_err());
    }
    #[test]
    fn native_answers_are_bounded_and_do_not_reset_the_deadline() {
        let mut state = answers(false);
        state.deadline = Instant::now() - Duration::from_millis(1);
        assert_eq!(
            state
                .accept(6, 2, "192.0.2.44".parse().unwrap())
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        let mut state = answers(false);
        for n in 1..=64 {
            state
                .accept(6, 3, IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, n)))
                .unwrap();
        }
        assert!(state.accept(6, 3, "198.51.100.1".parse().unwrap()).is_err());
    }
}
