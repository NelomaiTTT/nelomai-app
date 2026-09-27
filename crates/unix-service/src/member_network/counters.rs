//! Decrypted interface progress. UAPI RX includes keepalives/handshakes and
//! must not be used as proof that an IP data path is healthy.
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataCounters {
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
pub fn native(index: u32) -> io::Result<DataCounters> {
    use std::io::Read;
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    if index == 0 || unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
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
    Ok(DataCounters {
        sent_packets: read("tx_packets")?,
        received_packets: read("rx_packets")?,
    })
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
