//! Native interface evidence. UAPI RX includes keepalives/handshakes and
//! must not be used as proof that an IP data path is healthy.
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataCounters {
    /// Transmission attempts for failure evidence; Linux includes native drops.
    /// Growth alone does not prove successful delivery or readiness.
    pub sent_packets: u64,
    pub received_packets: u64,
}

pub fn read_owned(
    expected: u32,
    mut identity: impl FnMut() -> io::Result<u32>,
    read: impl FnOnce(u32) -> io::Result<DataCounters>,
) -> io::Result<DataCounters> {
    if expected == 0 || identity()? != expected {
        return Err(changed());
    }
    let counters = read(expected)?;
    if identity()? != expected {
        return Err(changed());
    }
    Ok(counters)
}
fn changed() -> io::Error {
    io::Error::other("member_interface_changed")
}

#[cfg(any(target_os = "linux", test))]
fn parse_counter(text: &str) -> io::Result<u64> {
    let digits = text.strip_suffix('\n').unwrap_or(text);
    if digits.is_empty() || digits.len() > 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    digits
        .parse()
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

#[cfg(target_os = "linux")]
pub fn native(_: u32) -> io::Result<DataCounters> {
    // Linux needs a retained per-member socket; sysfs RX counts WG control too.
    Err(io::ErrorKind::Unsupported.into())
}

/// Counts only incoming IP on one already-owned Linux member. No packet reads
/// or forwarding: PACKET_STATISTICS includes capture drops and resets on read.
#[cfg(target_os = "linux")]
pub(crate) struct ReceiveCounter {
    socket: OwnedFd,
    index: u32,
    received: Option<u64>,
}

#[cfg(target_os = "linux")]
impl ReceiveCounter {
    pub(crate) fn open(index: u32) -> io::Result<Self> {
        if index == 0 || index > i32::MAX as u32 {
            return Err(changed());
        }
        // Protocol zero receives nothing until the configured socket is bound.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let ignore_outgoing: libc::c_int = 1;
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_IGNORE_OUTGOING,
                (&ignore_outgoing as *const libc::c_int).cast(),
                std::mem::size_of_val(&ignore_outgoing) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // Protocol metadata works for both IP families without assuming an L2
        // header. Keep only one byte; the bounded capture queue need not drain.
        let mut filter = unsafe {
            [
                libc::BPF_STMT(
                    (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    (libc::SKF_AD_OFF + libc::SKF_AD_PROTOCOL) as u32,
                ),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    libc::ETH_P_IP as u32,
                    2,
                    0,
                ),
                libc::BPF_JUMP(
                    (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    libc::ETH_P_IPV6 as u32,
                    1,
                    0,
                ),
                libc::BPF_STMT((libc::BPF_RET | libc::BPF_K) as u16, 0),
                libc::BPF_STMT((libc::BPF_RET | libc::BPF_K) as u16, 1),
            ]
        };
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                (&program as *const libc::sock_fprog).cast(),
                std::mem::size_of_val(&program) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let address = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: index as i32,
            ..unsafe { std::mem::zeroed() }
        };
        if unsafe {
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            socket,
            index,
            received: Some(0),
        })
    }

    pub(crate) fn read(&mut self, index: u32) -> io::Result<DataCounters> {
        use std::io::Read;
        if index != self.index {
            return Err(changed());
        }
        // A failed/reset statistics read must never silently restart evidence.
        let previous = self.received.take().ok_or_else(changed)?;
        let fd = self.socket.as_raw_fd();
        let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
        if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
            return Err(io::ErrorKind::NotFound.into());
        }
        let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
            .to_str()
            .map_err(|_| changed())?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(changed());
        }
        let read = |key: &str| -> io::Result<u64> {
            let mut text = String::new();
            std::fs::File::open(format!("/sys/class/net/{name}/statistics/{key}"))?
                .take(64)
                .read_to_string(&mut text)?;
            parse_counter(&text)
        };
        let sent_packets = read("tx_packets")?
            .checked_add(read("tx_dropped")?)
            .ok_or(io::ErrorKind::InvalidData)?;
        let mut stats: libc::tpacket_stats = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&stats) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                (&mut stats as *mut libc::tpacket_stats).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if length as usize != std::mem::size_of_val(&stats) || stats.tp_packets < stats.tp_drops {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let received_packets = previous
            .checked_add(u64::from(stats.tp_packets))
            .ok_or(io::ErrorKind::InvalidData)?;
        self.received = Some(received_packets);
        Ok(DataCounters {
            sent_packets,
            received_packets,
        })
    }
}

#[cfg(target_os = "macos")]
pub fn native(index: u32) -> io::Result<DataCounters> {
    if index == 0 {
        return Err(changed());
    }
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let addresses = Addresses(head);
    let mut current = addresses.0;
    let mut found = None;
    while !current.is_null() {
        // getifaddrs owns every pointer until Addresses is dropped. AF_LINK's
        // ifa_data is the BSD if_data, NOT the larger if_data64 sysctl layout.
        let row = unsafe { &*current };
        if !row.ifa_addr.is_null()
            && !row.ifa_name.is_null()
            && !row.ifa_data.is_null()
            && unsafe { (*row.ifa_addr).sa_family as i32 } == libc::AF_LINK
            && unsafe { libc::if_nametoindex(row.ifa_name) } == index
        {
            if found.is_some() {
                return Err(changed());
            }
            let data = unsafe { std::ptr::read_unaligned(row.ifa_data.cast::<libc::if_data>()) };
            found = Some(DataCounters {
                sent_packets: u64::from(data.ifi_opackets),
                received_packets: u64::from(data.ifi_ipackets),
            });
        }
        current = row.ifa_next;
    }
    found.ok_or_else(|| io::ErrorKind::NotFound.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_replacement_discards_the_sample() {
        let mut identities = [Ok(17), Ok(18)].into_iter();
        assert!(read_owned(
            17,
            || identities.next().unwrap(),
            |_| Ok(DataCounters {
                sent_packets: 4,
                received_packets: 9
            })
        )
        .is_err());
    }
    #[test]
    fn missing_identity_never_reads_foreign_counters() {
        assert!(read_owned(
            17,
            || Err(io::ErrorKind::NotFound.into()),
            |_| panic!("foreign read")
        )
        .is_err());
    }
    #[test]
    fn counter_parse_rejects_negative_multiline_or_oversize_values() {
        assert_eq!(parse_counter("42\n").unwrap(), 42);
        for input in ["-1", "1\n2", "", " 42", "18446744073709551616"] {
            assert!(parse_counter(input).is_err());
        }
    }
}
