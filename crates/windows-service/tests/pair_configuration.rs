use nelomai_windows_service::redundancy::{pair_configuration, slot_configuration};
use nelomai_windows_service::ServiceError;

const PROFILE: &str = "[Interface]\nPrivateKey = synthetic-private\nAddress = 10.240.5.2/32\nDNS = 9.9.9.9, 1.1.1.1\nTable = auto\nListenPort = 51820\nJc = 4\nJmin = 40\nJmax = 70\nHeaderProtectionKey = synthetic-header\nContentPaddingAddition = 1\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nPresharedKey = synthetic-preshared\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\nPersistentKeepalive = 25\n";

#[test]
fn carrier_keeps_logical_network_and_members_keep_only_native_transport() {
    let rendered = pair_configuration(PROFILE).unwrap();
    assert_eq!(
        rendered.addresses,
        vec!["10.240.5.2/32".parse::<ipnet::IpNet>().unwrap()]
    );
    assert_eq!(
        rendered.dns,
        vec![
            "9.9.9.9".parse::<std::net::IpAddr>().unwrap(),
            "1.1.1.1".parse().unwrap()
        ]
    );
    assert_eq!(&*rendered.native, "[Interface]\nTable = off\nPrivateKey = synthetic-private\nJc = 4\nJmin = 40\nJmax = 70\nHeaderProtectionKey = synthetic-header\nContentPaddingAddition = 1\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nPresharedKey = synthetic-preshared\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\nPersistentKeepalive = 25\n");
    assert!(slot_configuration(PROFILE)
        .unwrap()
        .contains("Address = 10.240.5.2/32"));
}

#[test]
fn sibling_network_equality_ignores_peer_but_rejects_changed_address_or_dns() {
    let a = pair_configuration(PROFILE).unwrap();
    let b = pair_configuration(
        &PROFILE
            .replace("192.0.2.1:51820", "192.0.2.2:51821")
            .replace("0.0.0.0/0", "198.51.100.0/24")
            .replace(
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            ),
    )
    .unwrap();
    assert!(a.matches_network(&b));
    for changed in [
        PROFILE.replace("10.240.5.2/32", "10.240.5.3/32"),
        PROFILE.replace("9.9.9.9, 1.1.1.1", "1.1.1.1, 9.9.9.9"),
    ] {
        assert!(!a.matches_network(&pair_configuration(&changed).unwrap()));
    }
}

#[test]
fn optional_dns_is_not_invented_for_carrier() {
    let p = pair_configuration(&PROFILE.replace("DNS = 9.9.9.9, 1.1.1.1\n", "")).unwrap();
    assert!(p.dns.is_empty());
}

#[test]
fn pair_rejects_reserved_carrier_or_dns_address() {
    for ip in ["240.0.0.1", "250.1.2.3"] {
        assert!(matches!(
            pair_configuration(&PROFILE.replace("10.240.5.2/32", &format!("{ip}/32"))),
            Err(ServiceError::InvalidRequest)
        ));
        assert!(matches!(
            pair_configuration(&PROFILE.replace("9.9.9.9, 1.1.1.1", ip)),
            Err(ServiceError::InvalidRequest)
        ));
    }
}

#[test]
fn pair_network_fields_are_section_owned_and_dns_list_is_bounded() {
    for input in [
        PROFILE.replace("[Peer]", "Address6 = 2001:db8::2/128\n[Peer]"),
        PROFILE.replace("[Peer]", "DNS2 = 8.8.8.8\n[Peer]"),
        PROFILE.replace("[Peer]", "[Peer]\nMTU = 1400"),
        PROFILE.replace(
            "9.9.9.9, 1.1.1.1",
            &(1..=17)
                .map(|i| format!("10.1.1.{i}"))
                .collect::<Vec<_>>()
                .join(","),
        ),
    ] {
        assert!(matches!(
            pair_configuration(&input),
            Err(ServiceError::InvalidRequest)
        ));
    }
    let sixteen = (1..=16)
        .map(|i| format!("10.1.1.{i}"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        pair_configuration(&PROFILE.replace("9.9.9.9, 1.1.1.1", &sixteen))
            .unwrap()
            .dns
            .len(),
        16
    );
}

#[test]
fn pair_rejects_ambiguous_or_unsupported_network_intent_without_secret_errors() {
    let invalid = [
        PROFILE.replace("10.240.5.2/32", "10.240.5.2/24"),
        PROFILE.replace("10.240.5.2/32", "10.240.5.2/32, 10.240.5.3/32"),
        PROFILE.replace("10.240.5.2/32", "10.240.5.2/32, 2001:db8::2/128"),
        PROFILE.replace("10.240.5.2/32", "2001:db8::2/128"),
        PROFILE.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = ::/0"),
        PROFILE.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0"),
        PROFILE.replace(
            "Address = 10.240.5.2/32",
            "Address = 10.240.5.2/32\naDdReSs = 10.240.5.2/32",
        ),
        PROFILE.replace("DNS = 9.9.9.9, 1.1.1.1", "DNS = 9.9.9.9\nDNS = 1.1.1.1"),
        PROFILE.replace("DNS = 9.9.9.9, 1.1.1.1", "DNS = 9.9.9.9, 9.9.9.9"),
        PROFILE.replace("DNS = 9.9.9.9, 1.1.1.1", "DNS = 0.0.0.0"),
        PROFILE.replace("DNS = 9.9.9.9, 1.1.1.1", "DNS = ::1"),
        PROFILE.replace("Address =", "Addresses ="),
        PROFILE
            .replace("Address = 10.240.5.2/32\n", "")
            .replace("[Peer]", "[Peer]\nAddress = 10.240.5.2/32"),
        PROFILE
            .replace("DNS = 9.9.9.9, 1.1.1.1\n", "")
            .replace("[Peer]", "[Peer]\nDNS = 9.9.9.9"),
        PROFILE.replace("[Peer]", "PostUp = synthetic-secret-command\n[Peer]"),
        PROFILE.replace("Table = auto", "Table = auto\nTable = off"),
        PROFILE.replace("Jc = 4", "Jc = 4\nJc = 5"),
        PROFILE.replace("[Peer]", "[Peer]\nPrivateKey = synthetic-other"),
        PROFILE.replace("[Peer]", "AllowedIPs = 0.0.0.0/0\n[Peer]"),
        PROFILE.replace(
            "AllowedIPs = 0.0.0.0/0",
            "AllowedIPs = 0.0.0.0/0\nAllowedIPs = 198.51.100.0/24",
        ),
        PROFILE.replace("192.0.2.1:51820", "192.0.2.1:0"),
        format!("{PROFILE}\0synthetic-secret"),
        "x".repeat(nelomai_windows_service::MAX_FRAME_SIZE + 1),
    ];
    for input in invalid {
        assert!(matches!(
            pair_configuration(&input),
            Err(ServiceError::InvalidRequest)
        ));
    }
    for address in [
        "0.0.0.0/32",
        "127.0.0.1/32",
        "224.0.0.1/32",
        "255.255.255.255/32",
        "169.254.1.1/32",
    ] {
        assert!(matches!(
            pair_configuration(&PROFILE.replace("10.240.5.2/32", address)),
            Err(ServiceError::InvalidRequest)
        ));
    }
}
