//! Scoped Windows DNS Client queries retain the OS's DoH/DDR policy.
//! No custom server list, ordinary socket resolver or default-interface retry.
use super::{policy, Snapshot};
use std::{
    cell::UnsafeCell,
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{DNS_ERROR_RCODE_NAME_ERROR, DNS_INFO_NO_RECORDS, DNS_REQUEST_PENDING},
    NetworkManagement::Dns::{
        DnsCancelQuery, DnsFree, DnsFreeRecordList, DnsQueryEx, DNS_AAAA_DATA, DNS_A_DATA,
        DNS_QUERY_CANCEL, DNS_QUERY_REQUEST, DNS_QUERY_RESULT, DNS_RECORDA, DNS_TYPE_A,
        DNS_TYPE_AAAA,
    },
};

static ACTIVE_RESOLVES: AtomicUsize = AtomicUsize::new(0);
const MAX_RESOLVES: usize = 4;
const DNS_BUDGET: Duration = Duration::from_secs(7);

struct Permit;
impl Permit {
    fn acquire() -> io::Result<Arc<Self>> {
        ACTIVE_RESOLVES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_RESOLVES).then_some(active + 1)
            })
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "physical_dns_busy"))?;
        Ok(Arc::new(Self))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        ACTIVE_RESOLVES.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Query {
    _name: Vec<u16>,
    kind: u16,
    request: UnsafeCell<DNS_QUERY_REQUEST>,
    result: UnsafeCell<DNS_QUERY_RESULT>,
    cancel: UnsafeCell<DNS_QUERY_CANCEL>,
    complete: AtomicBool,
    sender: mpsc::Sender<io::Result<Vec<IpAddr>>>,
    // A timed-out caller cannot release the capacity while callbacks still own
    // its DNS requests. At most four resolves (eight A/AAAA queries) stay live.
    _permit: Arc<Permit>,
}
// WinDNS owns result/cancel writes until completion. The caller only invokes
// its documented cancellation operation; the callback alone consumes records.
// All three native buffers and QueryName remain at stable heap addresses.
unsafe impl Send for Query {}
unsafe impl Sync for Query {}

fn request(
    name: *const u16,
    index: u32,
    kind: u16,
    context: *mut core::ffi::c_void,
) -> io::Result<DNS_QUERY_REQUEST> {
    let query = policy::dns_query(index, kind)?;
    Ok(DNS_QUERY_REQUEST {
        Version: 1,
        QueryName: name,
        QueryType: query.kind,
        QueryOptions: query.options,
        InterfaceIndex: query.interface,
        pDnsServerList: ptr::null_mut(),
        pQueryCompletionCallback: Some(completed),
        pQueryContext: context,
    })
}

struct Pending(Arc<Query>);
impl Pending {
    fn start(
        name: Vec<u16>,
        index: u32,
        kind: u16,
        sender: mpsc::Sender<io::Result<Vec<IpAddr>>>,
        permit: Arc<Permit>,
    ) -> io::Result<Self> {
        let input = request(name.as_ptr(), index, kind, ptr::null_mut())?;
        let query = Arc::new(Query {
            _name: name,
            kind,
            request: UnsafeCell::new(input),
            result: UnsafeCell::new(DNS_QUERY_RESULT {
                Version: 1,
                ..Default::default()
            }),
            cancel: UnsafeCell::new(DNS_QUERY_CANCEL::default()),
            complete: AtomicBool::new(false),
            sender,
            _permit: permit,
        });
        // Reserve one strong reference exclusively for the callback. If the OS
        // completes inline it promises not to invoke that callback; invoke our
        // same completion path once, matching Microsoft's asynchronous sample.
        let owner = Arc::into_raw(query.clone());
        unsafe {
            (*query.request.get()).pQueryContext = owner.cast_mut().cast();
        }
        let status =
            unsafe { DnsQueryEx(query.request.get(), query.result.get(), query.cancel.get()) };
        if status != DNS_REQUEST_PENDING {
            if status != 0 {
                unsafe {
                    (*query.result.get()).QueryStatus = status;
                }
            }
            unsafe {
                completed(owner.cast(), query.result.get());
            }
        }
        Ok(Self(query))
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if !self.0.complete.load(Ordering::Acquire) {
            // Cancellation does not wait for the callback. Its reserved Arc
            // keeps every OS-visible buffer alive after this function returns.
            // This caller's Arc also retains the cancel buffer during the call.
            unsafe {
                DnsCancelQuery(self.0.cancel.get());
            }
        }
    }
}

struct Records(*mut DNS_RECORDA);
impl Drop for Records {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                DnsFree(self.0.cast(), DnsFreeRecordList);
            }
        }
    }
}

unsafe fn addresses(records: *const DNS_RECORDA, kind: u16) -> io::Result<Vec<IpAddr>> {
    let mut current = records;
    let mut count = 0;
    let mut result = Vec::new();
    while !current.is_null() {
        if count == 256 {
            return Err(io::Error::other("physical_dns_response_invalid"));
        }
        count += 1;
        let row = unsafe { &*current };
        // Only answer records of the requested family; CNAME traversal and
        // encrypted transport are performed by the Windows DNS Client.
        if row.wType == kind && unsafe { row.Flags.DW } & 3 == 1 {
            let address =
                if kind == DNS_TYPE_A && usize::from(row.wDataLength) >= size_of::<DNS_A_DATA>() {
                    IpAddr::V4(Ipv4Addr::from(
                        unsafe { row.Data.A.IpAddress }.to_ne_bytes(),
                    ))
                } else if kind == DNS_TYPE_AAAA
                    && usize::from(row.wDataLength) >= size_of::<DNS_AAAA_DATA>()
                {
                    IpAddr::V6(Ipv6Addr::from(unsafe { row.Data.AAAA.Ip6Address.IP6Byte }))
                } else {
                    return Err(io::Error::other("physical_dns_response_invalid"));
                };
            if policy::usable(address)
                && !matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local())
            {
                result.push(address);
            }
        }
        current = row.pNext;
    }
    result.sort();
    result.dedup();
    Ok(result)
}

unsafe extern "system" fn completed(
    context: *const core::ffi::c_void,
    result: *mut DNS_QUERY_RESULT,
) {
    // Exactly one callback (native or inline) consumes the reserved reference.
    let query = unsafe { Arc::from_raw(context.cast::<Query>()) };
    let answer = if result.is_null() {
        Err(io::Error::other("physical_dns_response_invalid"))
    } else {
        let result = unsafe { &*result };
        let _records = Records(result.pQueryRecords);
        if result.QueryStatus == DNS_INFO_NO_RECORDS
            || result.QueryStatus == DNS_ERROR_RCODE_NAME_ERROR as i32
        {
            Ok(Vec::new())
        } else if result.QueryStatus != 0 {
            Err(io::Error::from_raw_os_error(result.QueryStatus))
        } else {
            unsafe { addresses(result.pQueryRecords, query.kind) }
        }
    };
    query.complete.store(true, Ordering::Release);
    let _ = query.sender.send(answer);
}

pub(super) fn resolve(host: &str, expected: &Snapshot) -> io::Result<Vec<IpAddr>> {
    let deadline = Instant::now() + DNS_BUDGET;
    if host.is_empty()
        || host.len() > 253
        || host.parse::<IpAddr>().is_ok()
        || !host.contains('.')
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "physical_dns_name_invalid",
        ));
    }
    let fresh = super::snapshot()?;
    if expected
        .ipv4
        .as_ref()
        .is_some_and(|interface| fresh.ipv4.as_ref() != Some(interface))
        || expected
            .ipv6
            .as_ref()
            .is_some_and(|interface| fresh.ipv6.as_ref() != Some(interface))
    {
        return Err(io::Error::other("physical_route_or_identity_changed"));
    }
    let queries = policy::dns_queries([
        expected.ipv4.as_ref().map(|interface| interface.index),
        expected.ipv6.as_ref().map(|interface| interface.index),
    ])?;
    let permit = Permit::acquire()?;
    let name: Vec<u16> = format!("{}.", host.trim_end_matches('.'))
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let (sender, receiver) = mpsc::channel();
    let mut pending = Vec::new();
    for query in queries {
        pending.push(Pending::start(
            name.clone(),
            query.interface,
            query.kind,
            sender.clone(),
            permit.clone(),
        )?);
    }
    drop(sender);
    let mut result = Vec::new();
    let mut last_error = None;
    for _ in 0..pending.len() {
        match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ok(mut addresses)) => result.append(&mut addresses),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "physical_dns_timeout",
                ));
                break;
            }
        }
    }
    // Pending's Drop requests cancellation. Its heap state is released only
    // after the callback, even when the enclosing connection timed out first.
    drop(pending);
    result.sort();
    result.dedup();
    if result.is_empty() {
        Err(last_error.unwrap_or_else(|| io::Error::other("physical_dns_no_addresses")))
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::NetworkManagement::Dns::{DNS_RECORDA_0, DNS_RECORDA_1, IP6_ADDRESS};

    #[test]
    fn native_request_keeps_system_policy_scoped_interface_and_async_completion() {
        let name: Vec<u16> = "example.com.\0".encode_utf16().collect();
        let request = request(name.as_ptr(), 7, DNS_TYPE_A, ptr::null_mut()).unwrap();
        assert_eq!(request.Version, 1);
        assert_eq!(request.InterfaceIndex, 7);
        assert!(request.pDnsServerList.is_null());
        assert!(request.pQueryCompletionCallback.is_some());
        assert_eq!(request.QueryOptions, 0x19e8);
    }

    #[test]
    fn native_records_decode_only_valid_answer_addresses_of_requested_family() {
        let mut ipv6 = DNS_RECORDA {
            wType: DNS_TYPE_AAAA,
            wDataLength: 16,
            Flags: DNS_RECORDA_0 { DW: 1 },
            Data: DNS_RECORDA_1 {
                AAAA: DNS_AAAA_DATA {
                    Ip6Address: IP6_ADDRESS {
                        IP6Byte: "2001:db8::2".parse::<Ipv6Addr>().unwrap().octets(),
                    },
                },
            },
            ..Default::default()
        };
        let mut ipv4 = DNS_RECORDA {
            pNext: &mut ipv6,
            wType: DNS_TYPE_A,
            wDataLength: 4,
            Flags: DNS_RECORDA_0 { DW: 1 },
            Data: DNS_RECORDA_1 {
                A: DNS_A_DATA {
                    IpAddress: u32::from_ne_bytes([192, 0, 2, 2]),
                },
            },
            ..Default::default()
        };
        assert_eq!(
            unsafe { addresses(&ipv4, DNS_TYPE_A) }.unwrap(),
            vec!["192.0.2.2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            unsafe { addresses(&ipv4, DNS_TYPE_AAAA) }.unwrap(),
            vec!["2001:db8::2".parse::<IpAddr>().unwrap()]
        );
        ipv4.Flags = DNS_RECORDA_0 { DW: 3 }; // additional section
        assert!(unsafe { addresses(&ipv4, DNS_TYPE_A) }.unwrap().is_empty());
        ipv4.Flags = DNS_RECORDA_0 { DW: 1 };
        ipv4.wDataLength = 1;
        assert!(unsafe { addresses(&ipv4, DNS_TYPE_A) }.is_err());
    }
}
