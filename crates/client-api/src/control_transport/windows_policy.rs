//! Portable policy used by the Windows IP Helper adapter.
use std::{io, net::IpAddr};

pub(super) fn physical(kind: u32, tunnel: i32, status: i32, flags: u8, name: &str) -> bool {
    status == 1
        && tunnel == 0
        && matches!(kind, 6 | 71 | 243 | 244)
        && flags & 1 != 0
        && flags & 0xfa == 0
        && !name.trim().to_ascii_lowercase().starts_with("nelomai")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Candidate {
    pub index: u32,
    pub metric: u64,
    pub gateway: Option<IpAddr>,
}

pub(super) fn select(candidates: &[Candidate]) -> io::Result<Option<&Candidate>> {
    let Some(best) = candidates.iter().min_by_key(|candidate| candidate.metric) else {
        return Ok(None);
    };
    if candidates
        .iter()
        .filter(|candidate| candidate.metric == best.metric)
        .count()
        != 1
    {
        return Err(io::Error::other("physical_egress_ambiguous"));
    }
    Ok(Some(best))
}

pub(super) fn usable(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && match address {
            IpAddr::V4(ip) => !ip.is_broadcast() && ip.octets()[0] != 0 && ip.octets()[0] < 240,
            IpAddr::V6(ip) => ip.to_ipv4_mapped().is_none() && ip.segments()[0] & 0xffc0 != 0xfec0,
        }
}

pub(super) fn covers(network: IpAddr, prefix: u8, destination: IpAddr) -> bool {
    match (network, destination) {
        (IpAddr::V4(network), IpAddr::V4(destination)) if prefix <= 32 => {
            let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
            u32::from(network) & !mask == 0 && u32::from(network) == u32::from(destination) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(destination)) if prefix <= 128 => {
            let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
            u128::from(network) & !mask == 0
                && u128::from(network) == u128::from(destination) & mask
        }
        _ => false,
    }
}

pub(super) fn interface_value(ipv4: bool, index: u32) -> u32 {
    if ipv4 {
        index.to_be()
    } else {
        index
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ScopedDnsQuery {
    pub interface: u32,
    pub kind: u16,
    pub options: u64,
}

pub(super) fn dns_query(interface: u32, kind: u16) -> io::Result<ScopedDnsQuery> {
    if interface == 0 || !matches!(kind, 1 | 28) {
        return Err(io::Error::other("physical_dns_interface_unavailable"));
    }
    Ok(ScopedDnsQuery {
        interface,
        kind,
        options: 0x19e8,
    })
}

pub(super) fn dns_queries(interfaces: [Option<u32>; 2]) -> io::Result<Vec<ScopedDnsQuery>> {
    let mut queries = Vec::new();
    for (interface, kind) in interfaces.into_iter().zip([1, 28]) {
        if let Some(interface) = interface {
            queries.push(dns_query(interface, kind)?);
        }
    }
    if queries.is_empty() {
        return Err(io::Error::other("physical_dns_interface_unavailable"));
    }
    Ok(queries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_live_hardware_ethernet_wifi_and_wwan_are_physical() {
        for kind in [6, 71, 243, 244] {
            assert!(physical(kind, 0, 1, 1, "Ethernet"));
        }
        for (kind, tunnel, status, flags, name) in [
            (6, 0, 1, 0, "VPN"),
            (6, 0, 1, 3, "Filter"),
            (6, 0, 1, 129, "Endpoint"),
            (6, 0, 2, 1, "Down"),
            (6, 1, 1, 1, "Tunnel"),
            (23, 0, 1, 1, "PPP"),
            (131, 0, 1, 1, "Tunnel"),
            (6, 0, 1, 1, "Nelomai carrier"),
        ] {
            assert!(!physical(kind, tunnel, status, flags, name), "{name}");
        }
    }

    #[test]
    fn route_choice_uses_full_metric_and_rejects_equal_cost_paths() {
        let first = Candidate {
            index: 7,
            metric: 30,
            gateway: Some("192.0.2.1".parse().unwrap()),
        };
        let second = Candidate {
            index: 8,
            metric: 20,
            gateway: None,
        };
        assert_eq!(
            select(&[first.clone(), second.clone()]).unwrap(),
            Some(&second)
        );
        let tied = Candidate {
            metric: 20,
            ..first
        };
        assert!(select(&[tied, second]).is_err());
        assert_eq!(select(&[]).unwrap(), None);
    }

    #[test]
    fn dns_and_sources_reject_loopback_unspecified_and_multicast() {
        for address in [
            "0.0.0.0",
            "127.0.0.53",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "ff02::1",
            "::ffff:192.0.2.1",
        ] {
            assert!(!usable(address.parse().unwrap()), "{address}");
        }
        for address in ["192.0.2.2", "2001:db8::2", "fe80::1"] {
            assert!(usable(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn target_route_matching_keeps_family_prefix_and_canonical_network() {
        for (network, prefix, destination, expected) in [
            ("192.0.2.0", 24, "192.0.2.20", true),
            ("192.0.2.0", 24, "192.0.3.20", false),
            ("192.0.2.1", 24, "192.0.2.20", false),
            ("0.0.0.0", 0, "192.0.2.20", true),
            ("0.0.0.0", 33, "192.0.2.20", false),
            ("::", 0, "192.0.2.20", false),
            ("2001:db8::", 32, "2001:db8:1::1", true),
            ("2001:db8::", 32, "2001:db9::1", false),
            ("2001:db8::1", 32, "2001:db8::2", false),
            ("::", 129, "2001:db8::1", false),
        ] {
            assert_eq!(
                covers(
                    network.parse().unwrap(),
                    prefix,
                    destination.parse().unwrap()
                ),
                expected,
                "{network}/{prefix} {destination}"
            );
        }
    }

    #[test]
    fn ipv4_interface_option_uses_network_bytes_but_ipv6_uses_host_index() {
        assert_eq!(
            interface_value(true, 0x01020304).to_ne_bytes(),
            [1, 2, 3, 4]
        );
        assert_eq!(interface_value(false, 0x01020304), 0x01020304);
    }

    #[test]
    fn native_dns_request_is_scoped_and_cannot_retry_without_an_interface() {
        let query = dns_query(7, 1).unwrap();
        assert_eq!(query.interface, 7);
        assert_eq!(query.kind, 1);
        // BYPASS_CACHE | WIRE_ONLY | NO_LOCAL_NAME | NO_HOSTS_FILE |
        // NO_NETBT | NO_MULTICAST | TREAT_AS_FQDN. No protocol override.
        assert_eq!(query.options, 0x19e8);
        assert_eq!(dns_query(8, 28).unwrap().kind, 28);
        assert!(dns_query(0, 1).is_err());
        assert!(dns_query(7, 12).is_err());
    }

    #[test]
    fn native_dns_uses_only_the_families_selected_by_the_shared_dialer() {
        let queries = dns_queries([Some(7), None]).unwrap();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].interface, 7);
        assert_eq!(queries[0].kind, 1);
        let queries = dns_queries([None, Some(8)]).unwrap();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].interface, 8);
        assert_eq!(queries[0].kind, 28);
        assert_eq!(dns_queries([Some(7), Some(8)]).unwrap().len(), 2);
        assert!(dns_queries([None, None]).is_err());
        assert!(dns_queries([Some(0), None]).is_err());
    }
}
