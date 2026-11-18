use super::*;

#[test]
fn parses_compact_masks_and_keeps_global_and_member_rows_distinct() {
    let destination = "0.0.0.2/31".parse().unwrap();
    let link = [8, libc::AF_LINK as u8, 8, 0, 0, 0, 0, 0];
    let mut table = Vec::new();
    for flags in [libc::RTF_UP, libc::RTF_UP | libc::RTF_IFSCOPE] {
        let mut row = vec![0; size_of::<libc::rt_msghdr2>()];
        row[2] = libc::RTM_VERSION as u8;
        row[3] = libc::RTM_GET2 as u8;
        put(
            &mut row,
            offset_of!(libc::rt_msghdr2, rtm_index),
            8u16.to_ne_bytes(),
        );
        put(
            &mut row,
            offset_of!(libc::rt_msghdr2, rtm_flags),
            flags.to_ne_bytes(),
        );
        put(
            &mut row,
            offset_of!(libc::rt_msghdr2, rtm_addrs),
            (libc::RTA_DST | libc::RTA_GATEWAY | libc::RTA_NETMASK).to_ne_bytes(),
        );
        append_address(&mut row, &address("0.0.0.2".parse().unwrap()));
        append_address(&mut row, &link);
        append_address(&mut row, &[8, 0, 0, 0, 255, 255, 255, 254]);
        let length = row.len() as u16;
        put(&mut row, 0, length.to_ne_bytes());
        table.extend(row);
    }
    let keys = [
        (destination, RouteScope::Global),
        (destination, RouteScope::Member(8)),
        ("0.0.0.0/30".parse().unwrap(), RouteScope::Global),
    ];
    let rows = find_routes(&table, &keys).unwrap();
    for (actual, (_, scope)) in rows[..2].iter().zip(keys) {
        assert_eq!(
            actual.as_ref().unwrap(),
            &RouteValue {
                destination,
                scope,
                interface: 8,
                gateway: None,
                metric: 0,
            }
        );
    }
    assert!(rows[2].is_none());
    table.pop();
    assert!(find_routes(&table, &keys).is_err());
}

#[test]
fn change_message_preserves_prefix_and_uses_interface_as_direct_gateway() {
    let route = RouteValue {
        destination: "2001:db8:1::/64".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 11,
        gateway: None,
        metric: 0,
    };
    let link = [8, libc::AF_LINK as u8, 11, 0, 0, 0, 0, 0];
    let bytes = message(libc::RTM_CHANGE, &route, Some(&link)).unwrap();
    assert_eq!(bytes[3], libc::RTM_CHANGE as u8);
    assert_eq!(get_u16(&bytes, offset_of!(libc::rt_msghdr, rtm_index)), 0);
    let bits = get_i32(&bytes, offset_of!(libc::rt_msghdr, rtm_addrs));
    let addresses = sockaddrs(&bytes[size_of::<libc::rt_msghdr>()..], bits).unwrap();
    assert_eq!(addresses[1], Some(link.as_slice()));
    assert_eq!(prefix(addresses[2].unwrap(), false).unwrap(), 64);
    assert_eq!(
        get_i32(&bytes, offset_of!(libc::rt_msghdr, rtm_flags)) & libc::RTF_GATEWAY,
        0
    );
}

fn ipv4_row(ip: &str, flags: i32, gateway: &[u8], mask: Option<&[u8]>) -> Vec<u8> {
    let mut row = vec![0; size_of::<libc::rt_msghdr2>()];
    row[2] = libc::RTM_VERSION as u8;
    row[3] = libc::RTM_GET2 as u8;
    put(
        &mut row,
        offset_of!(libc::rt_msghdr2, rtm_index),
        8u16.to_ne_bytes(),
    );
    put(
        &mut row,
        offset_of!(libc::rt_msghdr2, rtm_flags),
        flags.to_ne_bytes(),
    );
    let bits =
        libc::RTA_DST | libc::RTA_GATEWAY | if mask.is_some() { libc::RTA_NETMASK } else { 0 };
    put(
        &mut row,
        offset_of!(libc::rt_msghdr2, rtm_addrs),
        bits.to_ne_bytes(),
    );
    append_address(&mut row, &address(ip.parse().unwrap()));
    append_address(&mut row, gateway);
    if let Some(mask) = mask {
        append_address(&mut row, mask);
    }
    let length = row.len() as u16;
    put(&mut row, 0, length.to_ne_bytes());
    row
}

#[test]
fn non_cidr_kernel_route_does_not_block_exact_lookup() {
    let link = [8, libc::AF_LINK as u8, 8, 0, 0, 0, 0, 0];
    let foreign_mask = [7, 0, 0, 0, 255, 255, 253];
    let mut dump = ipv4_row("198.19.136.0", libc::RTF_UP, &link, Some(&foreign_mask));
    let destination = "198.19.250.1/32".parse().unwrap();
    let key = [(destination, RouteScope::Global)];
    assert_eq!(find_routes(&dump, &key).unwrap(), vec![None]);
    dump.extend(ipv4_row(
        "198.19.250.1",
        libc::RTF_UP | libc::RTF_HOST,
        &link,
        None,
    ));
    assert_eq!(
        find_routes(&dump, &key).unwrap()[0]
            .as_ref()
            .unwrap()
            .destination,
        destination
    );
}

#[test]
fn explicit_link_layer_gateway_cannot_compare_as_direct() {
    let gateway = [
        14,
        libc::AF_LINK as u8,
        8,
        0,
        0,
        0,
        6,
        0,
        0x02,
        0xa1,
        0xb2,
        0xc3,
        0xd4,
        0xe5,
    ];
    let key = [("198.19.241.94/32".parse().unwrap(), RouteScope::Global)];
    let dump = ipv4_row(
        "198.19.241.94",
        libc::RTF_UP | libc::RTF_HOST,
        &gateway,
        None,
    );
    assert_eq!(
        find_routes(&dump, &key).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn global_ipv4_host_prefix_uses_full_mask_and_scoped_probe_is_host() {
    let mut route = RouteValue {
        destination: "198.19.237.100/32".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 8,
        gateway: None,
        metric: 0,
    };
    let link = [8, libc::AF_LINK as u8, 8, 0, 0, 0, 0, 0];
    let bytes = message(libc::RTM_ADD, &route, Some(&link)).unwrap();
    let flags = get_i32(&bytes, offset_of!(libc::rt_msghdr, rtm_flags));
    assert_eq!(flags & (libc::RTF_IFSCOPE | libc::RTF_HOST), 0);
    let bits = get_i32(&bytes, offset_of!(libc::rt_msghdr, rtm_addrs));
    let addresses = sockaddrs(&bytes[size_of::<libc::rt_msghdr>()..], bits).unwrap();
    assert_eq!(prefix(addresses[2].unwrap(), true), Some(32));

    route.scope = RouteScope::Member(8);
    let bytes = message(libc::RTM_ADD, &route, Some(&link)).unwrap();
    let flags = get_i32(&bytes, offset_of!(libc::rt_msghdr, rtm_flags));
    assert_eq!(
        flags & (libc::RTF_IFSCOPE | libc::RTF_HOST),
        libc::RTF_IFSCOPE | libc::RTF_HOST
    );
    let bits = get_i32(&bytes, offset_of!(libc::rt_msghdr, rtm_addrs));
    assert_eq!(bits & libc::RTA_NETMASK, 0);
}

#[test]
fn ignores_protocol_clones_with_the_same_key_as_a_static_route() {
    let link = [8, libc::AF_LINK as u8, 8, 0, 0, 0, 0, 0];
    let key = [("198.19.237.100/32".parse().unwrap(), RouteScope::Member(8))];
    let flags = libc::RTF_UP | libc::RTF_HOST | libc::RTF_IFSCOPE;
    let mut clone = ipv4_row("198.19.237.100", flags | libc::RTF_WASCLONED, &link, None);
    put(
        &mut clone,
        offset_of!(libc::rt_msghdr2, rtm_parentflags),
        libc::RTF_PRCLONING.to_ne_bytes(),
    );
    assert_eq!(find_routes(&clone, &key).unwrap(), vec![None]);
    clone.extend(ipv4_row(
        "198.19.237.100",
        flags | libc::RTF_STATIC,
        &link,
        None,
    ));
    assert_eq!(
        find_routes(&clone, &key).unwrap()[0]
            .as_ref()
            .unwrap()
            .interface,
        8
    );
}

#[test]
fn link_local_gateway_zone_must_match_the_outgoing_interface() {
    let gateway_ip = "fe80::1".parse().unwrap();
    let mut gateway = address(gateway_ip);
    put(&mut gateway, 24, 8u32.to_ne_bytes());
    assert_eq!(
        read_gateway(&gateway, libc::RTF_GATEWAY, 8).unwrap(),
        Some(gateway_ip)
    );
    assert!(read_gateway(&gateway, libc::RTF_GATEWAY, 9).is_err());
    put(&mut gateway, 10, 9u16.to_be_bytes());
    assert!(read_gateway(&gateway, libc::RTF_GATEWAY, 8).is_err());
}

const REPLY_PID: i32 = 647;
const REPLY_SEQUENCE: i32 = 26;

fn get_reply(route: &RouteValue, add_flags: i32) -> Vec<u8> {
    use libc::rt_msghdr as Header;

    let index = u16::try_from(route.interface).unwrap();
    let [lo, hi] = index.to_ne_bytes();
    let link = [8, libc::AF_LINK as u8, lo, hi, 0, 0, 0, 0];
    let mut reply = message(libc::RTM_GET, route, Some(&link)).unwrap();
    let flags = get_i32(&reply, offset_of!(Header, rtm_flags));
    put(
        &mut reply,
        offset_of!(Header, rtm_index),
        index.to_ne_bytes(),
    );
    put(
        &mut reply,
        offset_of!(Header, rtm_pid),
        REPLY_PID.to_ne_bytes(),
    );
    put(
        &mut reply,
        offset_of!(Header, rtm_seq),
        REPLY_SEQUENCE.to_ne_bytes(),
    );
    put(
        &mut reply,
        offset_of!(Header, rtm_flags),
        (flags | libc::RTF_DONE | add_flags).to_ne_bytes(),
    );
    reply
}

#[test]
fn get_and_change_use_the_same_kernel_lookup() {
    let route = RouteValue {
        destination: "198.19.244.33/32".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 8,
        gateway: None,
        metric: 0,
    };
    use libc::rt_msghdr as Header;

    let get = message(libc::RTM_GET, &route, None).unwrap();
    let link = [8, libc::AF_LINK as u8, 9, 0, 0, 0, 0, 0];
    let after = RouteValue {
        interface: 9,
        ..route
    };
    let change = message(libc::RTM_CHANGE, &after, Some(&link)).unwrap();
    let flags = offset_of!(Header, rtm_flags);
    let scope = offset_of!(Header, rtm_index);
    assert_eq!(get_i32(&get, flags), get_i32(&change, flags));
    assert_eq!(get_u16(&get, scope), get_u16(&change, scope));
    let addresses = |packet: &[u8]| {
        let fields = sockaddrs(
            &packet[size_of::<Header>()..],
            get_i32(packet, offset_of!(Header, rtm_addrs)),
        )
        .unwrap();
        (fields[0].unwrap().to_vec(), fields[2].unwrap().to_vec())
    };
    assert_eq!(addresses(&get), addresses(&change));
}

#[test]
fn rejects_scoped_or_cached_result_of_the_kernel_lookup() {
    let owned = RouteValue {
        destination: "198.19.244.33/32".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 8,
        gateway: None,
        metric: 0,
    };
    let reply = get_reply(&owned, 0);
    assert!(validate_get_reply(&reply, REPLY_PID, REPLY_SEQUENCE, &owned).unwrap());
    assert!(!validate_get_reply(&reply, REPLY_PID, REPLY_SEQUENCE + 1, &owned).unwrap());
    assert!(!validate_get_reply(&reply, REPLY_PID + 1, REPLY_SEQUENCE, &owned).unwrap());

    for flags in [libc::RTF_IFSCOPE, libc::RTF_WASCLONED] {
        let reply = get_reply(&owned, flags);
        assert!(validate_get_reply(&reply, REPLY_PID, REPLY_SEQUENCE, &owned).is_err());
    }
}

#[test]
fn rejects_a_lookup_answer_for_a_different_prefix_or_interface() {
    let owned = RouteValue {
        destination: "198.19.244.32/31".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 8,
        gateway: None,
        metric: 0,
    };
    let other_interface = RouteValue {
        interface: 9,
        ..owned.clone()
    };
    let other_prefix = RouteValue {
        destination: "198.19.244.32/30".parse().unwrap(),
        ..owned.clone()
    };
    for other in [other_interface, other_prefix] {
        let reply = get_reply(&other, 0);
        assert!(validate_get_reply(&reply, REPLY_PID, REPLY_SEQUENCE, &owned).is_err());
    }
}

#[test]
fn unexpected_maskless_row_blocks_only_its_native_key() {
    let link = [8, libc::AF_LINK as u8, 8, 0, 0, 0, 0, 0];
    let dump = ipv4_row("198.19.241.94", libc::RTF_UP, &link, None);
    let other = [("198.19.241.95/32".parse().unwrap(), RouteScope::Global)];
    let exact = [("198.19.241.94/32".parse().unwrap(), RouteScope::Global)];
    assert_eq!(find_routes(&dump, &other).unwrap(), vec![None]);
    assert_eq!(
        find_routes(&dump, &exact).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn native_host_replacement_cannot_be_changed_or_deleted_as_an_owned_ipv4_host_prefix() {
    let ip = "198.19.244.11";
    let link = [8, libc::AF_LINK as u8, 8, 0, 0, 0, 0, 0];
    let owned = RouteValue {
        destination: "198.19.244.11/32".parse().unwrap(),
        scope: RouteScope::Global,
        interface: 8,
        gateway: None,
        metric: 0,
    };
    let replacement = ipv4_row(
        ip,
        libc::RTF_UP | libc::RTF_STATIC | libc::RTF_HOST,
        &link,
        None,
    );
    let key = [(owned.destination, owned.scope)];
    assert_eq!(
        find_routes(&replacement, &key).unwrap(),
        vec![Some(owned.clone())]
    );

    let mask = [8, 0, 0, 0, 255, 255, 255, 255];
    let original = ipv4_row(ip, libc::RTF_UP | libc::RTF_STATIC, &link, Some(&mask));
    check_delete_owner(&original, &owned).unwrap();
    assert!(check_delete_owner(&replacement, &owned).is_err());

    // A maskless host response with the same address and interface can
    // still differ from the native route that was installed.
    use libc::rt_msghdr as Header;
    let mut host = owned.clone();
    host.scope = RouteScope::Member(8);
    let mut reply = get_reply(&host, 0);
    let flags = get_i32(&reply, offset_of!(Header, rtm_flags));
    put(
        &mut reply,
        offset_of!(Header, rtm_flags),
        (flags & !libc::RTF_IFSCOPE).to_ne_bytes(),
    );
    assert!(validate_get_reply(&reply, REPLY_PID, REPLY_SEQUENCE, &owned).is_err());
}

#[test]
fn delete_requires_the_static_flag_for_explicit_ipv4_masks() {
    let ip = "198.19.244.54";
    let link = [8, libc::AF_LINK as u8, 8, 0, 0, 0, 0, 0];
    for (prefix_len, mask_tail) in [(31, 254), (32, 255)] {
        let owned = RouteValue {
            destination: format!("{ip}/{prefix_len}").parse().unwrap(),
            scope: RouteScope::Global,
            interface: 8,
            gateway: None,
            metric: 0,
        };
        let mask = [8, 0, 0, 0, 255, 255, 255, mask_tail];
        let original = ipv4_row(ip, libc::RTF_UP | libc::RTF_STATIC, &link, Some(&mask));
        let replacement = ipv4_row(ip, libc::RTF_UP, &link, Some(&mask));
        check_delete_owner(&original, &owned).unwrap();
        assert_eq!(
            find_routes(&replacement, &[(owned.destination, owned.scope)]).unwrap(),
            vec![Some(owned.clone())]
        );
        assert!(
            check_delete_owner(&replacement, &owned).is_err(),
            "a nonstatic /{prefix_len} must be preserved"
        );
    }
}
