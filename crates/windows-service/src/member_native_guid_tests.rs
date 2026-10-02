use super::*;
// Independent EXE algorithm comparison only; this entire file is cfg(test).
// Primary reference: https://github.com/WireGuard/wireguard-windows/blob/4e6726c23ae9c5cb58e0c9910f3b7515621d133d/tunnel/deterministicguid.go
use std::net::IpAddr;
const MAX_ALLOWED_IPS: usize = 4096;
#[derive(Debug, Eq, PartialEq)]
enum ReferenceError {
    UnsupportedName,
    UnsupportedPeerCount,
    InvalidKey,
    UnsupportedAllowedIp,
    TooManyAllowedIps,
}
fn reference_hash_string(hash: &mut Blake2s256, text: &str) {
    hash.update((text.len() as u32).to_le_bytes());
    hash.update(text.as_bytes());
}

/// Decoded key and individual parsed-config AllowedIPs; not a raw wg-quick parser.
/// Endpoint/PSK/MTU/DNS/addresses/hooks are not GUID inputs in the audited source.
#[derive(Clone, Copy)]
struct WireGuardPeer<'a> {
    pub public_key: [u8; 32],
    pub allowed_ips: &'a [&'a str],
}
#[derive(Debug, Eq, PartialEq)]
struct ValidatedWireGuardInput {
    name: &'static str,
    interface_public_key: [u8; 32],
    peer_public_key: [u8; 32],
    allowed_ips: Vec<AllowedIp>,
}
impl ValidatedWireGuardInput {
    /// Restricts the reference algorithm to one peer and current ASCII WG slots.
    /// A borrowed private key is used only to derive the public key. This object
    /// retains no private key. The caller owns secret memory/zeroization; neither
    /// this function nor upstream ScalarBaseMult promises wiping every copy.
    /// Zero keys and oversized input are policy refusals, not Go equivalence.
    fn new(
        name: &str,
        secret: &[u8; 32],
        peers: &[WireGuardPeer<'_>],
    ) -> Result<Self, ReferenceError> {
        let name = match name {
            "nelomai-a" => "nelomai-a",
            "nelomai-b" => "nelomai-b",
            _ => return Err(ReferenceError::UnsupportedName),
        };
        let [peer] = peers else {
            return Err(ReferenceError::UnsupportedPeerCount);
        };
        if *secret == [0; 32] || peer.public_key == [0; 32] {
            return Err(ReferenceError::InvalidKey);
        }
        if peer.allowed_ips.len() > MAX_ALLOWED_IPS {
            return Err(ReferenceError::TooManyAllowedIps);
        }
        let mut allowed_ips = peer
            .allowed_ips
            .iter()
            .map(|ip| AllowedIp::parse(ip))
            .collect::<Result<Vec<_>, _>>()?;
        // Go service.DeduplicateNetworkEntries uses canonical String() equality.
        // For this accepted subset, (address,prefix) equality is identical.
        allowed_ips.sort_unstable_by_key(|ip| (ip.bit_len(), ip.prefix, ip.address));
        allowed_ips.dedup();
        let interface_public_key =
            x25519_dalek::x25519(*secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        Ok(Self {
            name,
            interface_public_key,
            peer_public_key: peer.public_key,
            allowed_ips,
        })
    }
    fn interface_public_key(&self) -> [u8; 32] {
        self.interface_public_key
    }
    /// Matches the audited upstream EXE algorithm, not a shipped EXE identity.
    /// Deliberately separate from ValidatedMember: must not precreate registry
    /// keys for an unpinned executable based on this reference result.
    fn reference_executable_guid(&self) -> NativeGuid {
        let mut hash = Blake2s256::new();
        hash.update(b"Deterministic WireGuard Windows GUID v1 jason@zx2c4.com");
        reference_hash_string(&mut hash, self.name);
        hash.update(self.interface_public_key);
        hash.update(1u32.to_le_bytes());
        hash.update(self.peer_public_key);
        // Bounded at construction, before dedup; fits LE u32 without truncation.
        hash.update((self.allowed_ips.len() as u32).to_le_bytes());
        for ip in &self.allowed_ips {
            reference_hash_string(&mut hash, &format!("{}/{}", ip.address, ip.prefix));
        }
        {
            let digest = hash.finalize();
            let mut memory = [0; 16];
            memory.copy_from_slice(&digest[..16]);
            NativeGuid(memory)
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct AllowedIp {
    address: IpAddr,
    prefix: u8,
}
impl AllowedIp {
    fn bit_len(&self) -> u8 {
        if self.address.is_ipv4() {
            32
        } else {
            128
        }
    }
    fn parse(text: &str) -> Result<Self, ReferenceError> {
        // Refuse syntax outside the audited cross-language subset, rather than
        // trim/unmap/repair it. IPv4-mapped IPv6 netip formatting is excluded.
        if text.len() > 64 || !text.is_ascii() || text.trim() != text {
            return Err(ReferenceError::UnsupportedAllowedIp);
        }
        let (address, prefix_text) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let address: IpAddr = address
            .parse()
            .map_err(|_| ReferenceError::UnsupportedAllowedIp)?;
        if let IpAddr::V6(v6) = address {
            if v6.to_ipv4_mapped().is_some() {
                return Err(ReferenceError::UnsupportedAllowedIp);
            }
        }
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            None => bits,
            Some(value) => {
                if value.is_empty()
                    || value.len() > 3
                    || !value.bytes().all(|b| b.is_ascii_digit())
                    || (value.len() > 1 && value.starts_with('0'))
                {
                    return Err(ReferenceError::UnsupportedAllowedIp);
                }
                value
                    .parse::<u8>()
                    .map_err(|_| ReferenceError::UnsupportedAllowedIp)?
            }
        };
        if prefix > bits {
            return Err(ReferenceError::UnsupportedAllowedIp);
        }
        // Do not mask host bits: Go parseIPCidr returns netip.ParsePrefix as-is.
        Ok(Self { address, prefix })
    }
}
use nelomai_client_tunnel::TunnelTransport;
use std::path::PathBuf;

fn config_path(filename: &str) -> PathBuf {
    Path::new(if cfg!(windows) {
        "C:/trusted/config"
    } else {
        "/trusted/config"
    })
    .join(filename)
}

// Break caught: hashing SCM names, swapping roles, using Windows-memory bytes
// in a canonical Binding, or selecting a caller-supplied registry root.
#[test]
fn actual_member_bindings_match_literal_guid_name_role_and_registry_path() {
    for (provider, revision, slot, file, service, expected) in [
        (ProviderPath::WireGuardSignedDll, WG_SOURCE_REVISION, TunnelSlot::A,
         "nelomai-a.conf", "WireGuardTunnel$nelomai-a", receipt::Binding {
            role: receipt::Role::MemberA, guid: bytes("b75141b9108e4bf95a477af4a3ddcd39"),
            name: "nelomai-a".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{b75141b9-108e-4bf9-5a47-7af4a3ddcd39}".into(),
         }),
        (ProviderPath::WireGuardSignedDll, WG_SOURCE_REVISION, TunnelSlot::B,
         "nelomai-b.conf", "WireGuardTunnel$nelomai-b", receipt::Binding {
            role: receipt::Role::MemberB, guid: bytes("2bb164068cb140d23fa0c71e3be8ca2d"),
            name: "nelomai-b".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{2bb16406-8cb1-40d2-3fa0-c71e3be8ca2d}".into(),
         }),
        (ProviderPath::AmneziaSignedDll, AWG_SOURCE_REVISION, TunnelSlot::A,
         "nelomai-a.conf", "NelomaiAmneziaWg3A", receipt::Binding {
            role: receipt::Role::MemberA, guid: bytes("5e421b1932345defd557e8c3d50a2247"),
            name: "NelomaiAmneziaWg3A".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{5e421b19-3234-5def-d557-e8c3d50a2247}".into(),
         }),
        (ProviderPath::AmneziaSignedDll, AWG_SOURCE_REVISION, TunnelSlot::B,
         "nelomai-b.conf", "NelomaiAmneziaWg3B", receipt::Binding {
            role: receipt::Role::MemberB, guid: bytes("adf8d2506db6d0a8bed5b6f47b94f340"),
            name: "NelomaiAmneziaWg3B".into(), registry_path: r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{adf8d250-6db6-d0a8-bed5-b6f47b94f340}".into(),
         }),
    ] {
        assert_eq!(member_binding(provider, revision, slot, &config_path(file), service), Ok(expected));
    }
}

#[test]
fn binding_names_follow_actual_slot_service_specs() {
    for slot in [TunnelSlot::A, TunnelSlot::B] {
        for (provider, revision, transport) in [
            (
                ProviderPath::WireGuardSignedDll,
                WG_SOURCE_REVISION,
                TunnelTransport::WireGuard,
            ),
            (
                ProviderPath::AmneziaSignedDll,
                AWG_SOURCE_REVISION,
                TunnelTransport::AmneziaWg3,
            ),
        ] {
            let path = config_path(crate::redundancy::slot_config_filename(slot));
            let executable = config_path("nelomai-windows-service.exe");
            let spec =
                crate::redundancy::slot_service_spec(&executable, &path, slot, transport).unwrap();
            let binding = member_binding(provider, revision, slot, &path, &spec.name).unwrap();
            assert_eq!(
                binding.name,
                match transport {
                    TunnelTransport::WireGuard => path.file_stem().unwrap().to_str().unwrap(),
                    TunnelTransport::AmneziaWg3 => spec.name.as_str(),
                }
            );
        }
    }
}

// Break caught: accepting ordinary/foreign config, basename or normalization
// aliases, wrong-slot config, a changed suffix or non-UTF8 native filenames.
#[test]
fn binding_rejects_alias_and_non_member_configuration_paths() {
    let mut invalid = vec![
        PathBuf::new(),
        PathBuf::from("nelomai-a.conf"),
        config_path("."),
    ];
    for name in [
        "nelomai.conf",
        "nelomai-b.conf",
        "Nelomai-a.conf",
        "nelomai-a.CONF",
        "nelomai-a.conf.dpapi",
        "nelomai-a.conf.",
        "nelomai-a.conf ",
        "nelomai-a.conf:stream",
        "nelomai-a.conf.bak",
        "nelomai-a",
        "nelomai-a.cоnf",
        "nelomai-а.conf",
        "nelomai-a.conf\0",
        "nelomai-a.conf/",
        "nelomai-a.conf/.",
        "./nelomai-a.conf",
        "../config/nelomai-a.conf",
        "nested/../nelomai-a.conf",
        "nested//nelomai-a.conf",
        "quote\"/nelomai-a.conf",
        "control\n/nelomai-a.conf",
        "foreign.conf",
    ] {
        invalid.push(config_path(name));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        invalid.push(
            config_path("unused")
                .with_file_name(std::ffi::OsString::from_vec(b"nelomai-a.conf\xff".to_vec())),
        );
        invalid.push(config_path("nested\\nelomai-a.conf"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let mut name: Vec<u16> = "nelomai-a.conf".encode_utf16().collect();
        name.push(0xd800);
        invalid.push(config_path("unused").with_file_name(std::ffi::OsString::from_wide(&name)));
    }
    for path in invalid {
        for (provider, revision, service) in [
            (
                ProviderPath::WireGuardSignedDll,
                WG_SOURCE_REVISION,
                "WireGuardTunnel$nelomai-a",
            ),
            (
                ProviderPath::AmneziaSignedDll,
                AWG_SOURCE_REVISION,
                "NelomaiAmneziaWg3A",
            ),
        ] {
            assert_eq!(
                member_binding(provider, revision, TunnelSlot::A, &path, service),
                Err(GuidError::InvalidConfigurationPath),
                "accepted {path:?}"
            );
        }
    }
}

#[test]
fn binding_rejects_foreign_ordinary_alias_and_wrong_transport_services() {
    for (provider, revision, valid) in [
        (
            ProviderPath::WireGuardSignedDll,
            WG_SOURCE_REVISION,
            "WireGuardTunnel$nelomai-a",
        ),
        (
            ProviderPath::AmneziaSignedDll,
            AWG_SOURCE_REVISION,
            "NelomaiAmneziaWg3A",
        ),
    ] {
        for service in [
            "",
            "Nelomai",
            "NelomaiTunnelManager",
            "WireGuardTunnel$Nelomai",
            "NelomaiAmneziaWg3",
            "WireGuardTunnel$nelomai-b",
            "NelomaiAmneziaWg3B",
            "wireguardtunnel$nelomai-a",
            "nelomaiamneziawg3a",
            "nelomai-a",
            "foreign",
            "WireGuardTunnel$nelomai-a ",
            "NelomaiAmneziaWg3A\0",
            "NеlomaiAmneziaWg3A",
            if valid == "WireGuardTunnel$nelomai-a" {
                "NelomaiAmneziaWg3A"
            } else {
                "WireGuardTunnel$nelomai-a"
            },
        ] {
            assert_eq!(
                member_binding(
                    provider,
                    revision,
                    TunnelSlot::A,
                    &config_path("nelomai-a.conf"),
                    service
                ),
                Err(GuidError::ServiceNameMismatch),
                "accepted {service:?}"
            );
        }
    }
}

#[test]
fn binding_refuses_unsupported_provider_and_unmatched_revision_before_other_inputs() {
    for provider in [
        ProviderPath::WireGuardExeInstallTunnelService,
        ProviderPath::Unsupported,
    ] {
        assert_eq!(
            member_binding(
                provider,
                WG_SOURCE_REVISION,
                TunnelSlot::A,
                Path::new(""),
                ""
            ),
            Err(GuidError::UnsupportedPath)
        );
        assert_eq!(
            member_binding(
                provider,
                WG_SOURCE_REVISION,
                TunnelSlot::A,
                &config_path("nelomai-a.conf"),
                "WireGuardTunnel$nelomai-a"
            ),
            Err(GuidError::UnsupportedPath)
        );
    }
    for (provider, revisions) in [
        (
            ProviderPath::WireGuardSignedDll,
            [AWG_SOURCE_REVISION, "", "latest", "4e6726c2"],
        ),
        (
            ProviderPath::AmneziaSignedDll,
            [WG_SOURCE_REVISION, "", "latest", "575626d8"],
        ),
    ] {
        for revision in revisions {
            assert_eq!(
                member_binding(provider, revision, TunnelSlot::B, Path::new(""), ""),
                Err(GuidError::UnsupportedRevision)
            );
        }
    }
}

#[test]
fn binding_cannot_relabel_a_sibling_slot_for_either_provider() {
    for (provider, revision, slot, file, service, foreign_file, foreign_service) in [
        (
            ProviderPath::WireGuardSignedDll,
            WG_SOURCE_REVISION,
            TunnelSlot::A,
            "nelomai-a.conf",
            "WireGuardTunnel$nelomai-a",
            "nelomai-b.conf",
            "WireGuardTunnel$nelomai-b",
        ),
        (
            ProviderPath::WireGuardSignedDll,
            WG_SOURCE_REVISION,
            TunnelSlot::B,
            "nelomai-b.conf",
            "WireGuardTunnel$nelomai-b",
            "nelomai-a.conf",
            "WireGuardTunnel$nelomai-a",
        ),
        (
            ProviderPath::AmneziaSignedDll,
            AWG_SOURCE_REVISION,
            TunnelSlot::A,
            "nelomai-a.conf",
            "NelomaiAmneziaWg3A",
            "nelomai-b.conf",
            "NelomaiAmneziaWg3B",
        ),
        (
            ProviderPath::AmneziaSignedDll,
            AWG_SOURCE_REVISION,
            TunnelSlot::B,
            "nelomai-b.conf",
            "NelomaiAmneziaWg3B",
            "nelomai-a.conf",
            "NelomaiAmneziaWg3A",
        ),
    ] {
        assert_eq!(
            member_binding(
                provider,
                revision,
                slot,
                &config_path(foreign_file),
                service
            ),
            Err(GuidError::InvalidConfigurationPath)
        );
        assert_eq!(
            member_binding(
                provider,
                revision,
                slot,
                &config_path(file),
                foreign_service
            ),
            Err(GuidError::ServiceNameMismatch)
        );
    }
}

// Break caught: hashing a config-dependent label, setting UUID version/variant
// bits, or treating digest bytes as network-order GUID bytes.
#[test]
fn signed_awg_observed_guid_is_raw_windows_memory_order() {
    // User-supplied own signed-AWG observation, 2026-09-30.
    let guid = fixed_name_guid("NelomaiAmneziaWg3");
    assert_eq!(guid.to_string(), "093889e9-0638-2af7-e890-8f81b9e9c695");
    assert_eq!(
        guid.windows_memory_bytes(),
        [
            0xe9, 0x89, 0x38, 0x09, 0x38, 0x06, 0xf7, 0x2a, 0xe8, 0x90, 0x8f, 0x81, 0xb9, 0xe9,
            0xc6, 0x95
        ]
    );
}

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
}

const ALICE_SECRET: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const MIXED_IPS: &[&str] = &[
    "::/0",
    "10.9.8.7/24",
    "0.0.0.0/0",
    "192.0.2.5",
    "2001:0db8::2/64",
    "0.0.0.0/0",
];

fn wg_input(name: &str, ips: &[&str]) -> ValidatedWireGuardInput {
    ValidatedWireGuardInput::new(
        name,
        &bytes(ALICE_SECRET),
        &[WireGuardPeer {
            public_key: bytes(BOB_PUBLIC),
            allowed_ips: ips,
        }],
    )
    .unwrap()
}

// Break caught: changing labels, names, LE length prefixes or digest byte order.
#[test]
fn pinned_dll_member_vectors_match_independent_blake2s() {
    for (path, revision, slot, name, expected) in [
        (
            ProviderPath::AmneziaSignedDll,
            AWG_SOURCE_REVISION,
            MemberSlot::A,
            "NelomaiAmneziaWg3A",
            "5e421b19-3234-5def-d557-e8c3d50a2247",
        ),
        (
            ProviderPath::AmneziaSignedDll,
            AWG_SOURCE_REVISION,
            MemberSlot::B,
            "NelomaiAmneziaWg3B",
            "adf8d250-6db6-d0a8-bed5-b6f47b94f340",
        ),
        (
            ProviderPath::WireGuardSignedDll,
            WG_SOURCE_REVISION,
            MemberSlot::A,
            "nelomai-a",
            "b75141b9-108e-4bf9-5a47-7af4a3ddcd39",
        ),
        (
            ProviderPath::WireGuardSignedDll,
            WG_SOURCE_REVISION,
            MemberSlot::B,
            "nelomai-b",
            "2bb16406-8cb1-40d2-3fa0-c71e3be8ca2d",
        ),
    ] {
        let input = ValidatedMember::new(path, revision, slot, name).unwrap();
        assert_eq!(input.guid().to_string(), expected);
        assert_eq!(input.path(), path);
        assert_eq!(input.slot(), slot);
        assert_eq!(input.native_name(), name);
    }
}

// Recorded Panel research: WINDOWS-SHARED-VIP-RESEARCH-2026-09-29.md,
// "Real addressless AWG under triple policy, 12:20UTC". No new native probe.
#[test]
fn recorded_own_probe_guid_matches_the_fixed_algorithm() {
    assert_eq!(
        fixed_name_guid("Nelomai-AWG-Probe-36555129204").to_string(),
        "c3b985a4-391b-1d24-c2b6-2c16252b1a16"
    );
}

// Break caught: feeding Windows memory bytes into a canonical-byte consumer.
#[test]
fn canonical_bytes_native_fields_and_registry_component_agree() {
    let guid = fixed_name_guid("NelomaiAmneziaWg3");
    assert_eq!(
        guid.canonical_bytes(),
        bytes("093889e906382af7e8908f81b9e9c695")
    );
    assert_eq!(
        guid.windows_fields(),
        WindowsGuidFields {
            data1: 0x093889e9,
            data2: 0x0638,
            data3: 0x2af7,
            data4: bytes("e8908f81b9e9c695"),
        }
    );
    assert_eq!(
        guid.registry_component(),
        "{093889e9-0638-2af7-e890-8f81b9e9c695}"
    );
}

// Break caught: accepting an unaudited provider/revision as the AWG default.
#[test]
fn executable_and_unknown_paths_fail_even_with_a_known_revision() {
    for path in [
        ProviderPath::WireGuardExeInstallTunnelService,
        ProviderPath::Unsupported,
    ] {
        assert_eq!(
            ValidatedMember::new(path, WG_SOURCE_REVISION, MemberSlot::A, "nelomai-a"),
            Err(GuidError::UnsupportedPath)
        );
    }
}

#[test]
fn dll_revisions_are_independent_and_exact() {
    for (path, name, wrong) in [
        (
            ProviderPath::AmneziaSignedDll,
            "NelomaiAmneziaWg3A",
            WG_SOURCE_REVISION,
        ),
        (
            ProviderPath::WireGuardSignedDll,
            "nelomai-a",
            AWG_SOURCE_REVISION,
        ),
    ] {
        for revision in [
            wrong,
            "",
            "latest",
            "575626d8",
            " 575626d8f8aa5b64114cf378a08e54bf852d909b",
        ] {
            assert_eq!(
                ValidatedMember::new(path, revision, MemberSlot::A, name),
                Err(GuidError::UnsupportedRevision)
            );
        }
    }
}

// Break caught: case folding, Unicode NFC guessing, service-name hashing,
// basename guessing, legacy-slot adoption or accepting an alias for slot A.
#[test]
fn only_exact_existing_slot_names_can_be_member_bindings() {
    for name in [
        "",
        "nelomai-b",
        "Nelomai-a",
        "NELОMAI-a",
        "nelomai-a\0",
        " nelomai-a",
        "nelomai-a ",
        "nelomai-a.conf",
        "WireGuardTunnel$nelomai-a",
        "../nelomai-a",
        "nelomai-a\\x",
        "Nelomai",
        "NelomaiAmneziaWg3A",
    ] {
        assert_eq!(
            ValidatedMember::new(
                ProviderPath::WireGuardSignedDll,
                WG_SOURCE_REVISION,
                MemberSlot::A,
                name
            ),
            Err(GuidError::UnsupportedName)
        );
    }
    for name in [
        "NelomaiAmneziaWg3",
        "NelomaiAmneziaWg3B",
        "nelomaiamneziawg3a",
        "nelomai-a",
    ] {
        assert_eq!(
            ValidatedMember::new(
                ProviderPath::AmneziaSignedDll,
                AWG_SOURCE_REVISION,
                MemberSlot::A,
                name
            ),
            Err(GuidError::UnsupportedName)
        );
    }
}

// Break caught: hashing the private key directly or deriving a wrong public key.
#[test]
fn interface_public_key_is_derived_from_the_rfc7748_private_key() {
    assert_eq!(
        wg_input("nelomai-a", &[]).interface_public_key(),
        bytes(ALICE_PUBLIC)
    );
}

// Break caught: applying the DLL fixed-name branch to an executable config,
// failing dedup, or sorting by address before prefix length/family.
#[test]
fn executable_reference_mixed_allowed_ips_matches_independent_vectors() {
    for (name, expected) in [
        ("nelomai-a", "249fed80-0f33-e44e-65b4-11735e8905ca"),
        ("nelomai-b", "bff4c0c8-0882-1583-d9f2-28fa7f7b02b2"),
    ] {
        assert_eq!(
            wg_input(name, MIXED_IPS)
                .reference_executable_guid()
                .to_string(),
            expected
        );
    }
}

#[test]
fn executable_reference_empty_allowed_ips_hashes_a_zero_count() {
    assert_eq!(
        wg_input("nelomai-a", &[])
            .reference_executable_guid()
            .to_string(),
        "c5de8d75-cc06-ed86-53a0-00b364084fc4"
    );
}

// Break caught: truncating networks to their masked base, which netip does not do.
#[test]
fn allowed_ip_host_bits_are_preserved_in_guid_hashes() {
    assert_eq!(
        wg_input("nelomai-a", &["10.9.8.0/24"])
            .reference_executable_guid()
            .to_string(),
        "de8ea5ce-90ee-adcd-425c-2547f5ceaa55"
    );
    assert_eq!(
        wg_input("nelomai-a", &["10.9.8.7/24"])
            .reference_executable_guid()
            .to_string(),
        "9f77b43f-7149-4a48-8f33-80cf0de167f8"
    );
}

#[test]
fn allowed_ips_are_canonicalized_sorted_and_deduplicated_without_mutating_input() {
    let original = MIXED_IPS.to_vec();
    let mut permuted = original.clone();
    permuted.reverse();
    permuted.extend(["2001:db8:0:0:0:0:0:2/64", "192.0.2.5/32"]);
    let input = wg_input("nelomai-a", &permuted);
    assert_eq!(
        input.reference_executable_guid().to_string(),
        "249fed80-0f33-e44e-65b4-11735e8905ca"
    );
    assert_eq!(MIXED_IPS, original);
}

#[test]
fn scalar_clamping_matches_go_scalar_base_mult() {
    let mut secret = bytes::<32>(ALICE_SECRET);
    secret[0] ^= 7;
    secret[31] ^= 0xc0;
    let input = ValidatedWireGuardInput::new(
        "nelomai-a",
        &secret,
        &[WireGuardPeer {
            public_key: bytes(BOB_PUBLIC),
            allowed_ips: MIXED_IPS,
        }],
    )
    .unwrap();
    assert_eq!(
        input.reference_executable_guid().to_string(),
        "249fed80-0f33-e44e-65b4-11735e8905ca"
    );
}

#[test]
fn reference_input_rejects_zero_or_multiple_peers_before_derivation() {
    let peer = WireGuardPeer {
        public_key: bytes(BOB_PUBLIC),
        allowed_ips: &[],
    };
    for peers in [&[][..], &[peer, peer][..]] {
        assert_eq!(
            ValidatedWireGuardInput::new("nelomai-a", &bytes(ALICE_SECRET), peers),
            Err(ReferenceError::UnsupportedPeerCount)
        );
    }
}

#[test]
fn reference_input_rejects_unscoped_names_and_empty_keys() {
    let peer = WireGuardPeer {
        public_key: bytes(BOB_PUBLIC),
        allowed_ips: &[],
    };
    for name in [
        "Nelomai",
        "nelomai-a.conf",
        "NelomaiAmneziaWg3A",
        "nélo",
        "nelomai-a\0",
    ] {
        assert_eq!(
            ValidatedWireGuardInput::new(name, &bytes(ALICE_SECRET), &[peer]),
            Err(ReferenceError::UnsupportedName)
        );
    }
    assert_eq!(
        ValidatedWireGuardInput::new("nelomai-a", &[0; 32], &[peer]),
        Err(ReferenceError::InvalidKey)
    );
    assert_eq!(
        ValidatedWireGuardInput::new(
            "nelomai-a",
            &bytes(ALICE_SECRET),
            &[WireGuardPeer {
                public_key: [0; 32],
                allowed_ips: &[]
            }]
        ),
        Err(ReferenceError::InvalidKey)
    );
}

// Break caught: silently accepting address syntax with different Go semantics.
#[test]
fn reference_input_refuses_unsupported_ip_forms_and_unbounded_lists() {
    for ip in [
        "",
        " 192.0.2.1/32",
        "192.0.2.1/32 ",
        "192.0.2.1/33",
        "::/129",
        "192.0.2.1/-1",
        "192.0.2.1/01",
        "192.0.2.1/+1",
        "192.0.2.1/",
        "192.0.2.1/32/32",
        "192.000.2.1/32",
        "host.example/32",
        "[::1]/128",
        "fe80::1%7/64",
        "::ffff:192.0.2.1/128",
        "::ffff:c000:201/128",
    ] {
        assert_eq!(
            ValidatedWireGuardInput::new(
                "nelomai-a",
                &bytes(ALICE_SECRET),
                &[WireGuardPeer {
                    public_key: bytes(BOB_PUBLIC),
                    allowed_ips: &[ip]
                }]
            ),
            Err(ReferenceError::UnsupportedAllowedIp),
            "accepted {ip:?}"
        );
    }
    let too_many = vec!["0.0.0.0/0"; MAX_ALLOWED_IPS + 1];
    assert_eq!(
        ValidatedWireGuardInput::new(
            "nelomai-a",
            &bytes(ALICE_SECRET),
            &[WireGuardPeer {
                public_key: bytes(BOB_PUBLIC),
                allowed_ips: &too_many
            }]
        ),
        Err(ReferenceError::TooManyAllowedIps)
    );
}

// Independent Go netip oracle: prefix length precedes address; addresses compare
// numerically, not lexically; IPv6 compresses the first longest zero run.
#[test]
fn prefix_sort_and_ipv6_compression_match_go_not_string_order() {
    let ips = [
        "2001:db8:0:1:0:0:0:1/64",
        "2001:db8:0:0:1:0:0:1/64",
        "192.0.2.200/32",
        "192.0.2.3/32",
        "10.1.2.3/8",
        "0.1.2.3/32",
    ];
    assert_eq!(
        wg_input("nelomai-a", &ips)
            .reference_executable_guid()
            .to_string(),
        "d05bc395-5172-636b-45c5-9e5a789ba7a0"
    );
}

// Break caught: accidentally retaining the fixed branch or omitting either key.
#[test]
fn both_interface_and_peer_public_keys_affect_the_executable_reference() {
    let peer = WireGuardPeer {
        public_key: bytes(BOB_PUBLIC),
        allowed_ips: &[],
    };
    let changed_interface = ValidatedWireGuardInput::new("nelomai-a", &[1; 32], &[peer]).unwrap();
    assert_eq!(
        changed_interface.interface_public_key(),
        bytes("a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209")
    );
    assert_eq!(
        changed_interface.reference_executable_guid().to_string(),
        "54a820cc-a893-5b72-4ea0-ed8741f34e88"
    );
    let changed_peer = ValidatedWireGuardInput::new(
        "nelomai-a",
        &bytes(ALICE_SECRET),
        &[WireGuardPeer {
            public_key: [2; 32],
            allowed_ips: &[],
        }],
    )
    .unwrap();
    assert_eq!(
        changed_peer.reference_executable_guid().to_string(),
        "a62c077e-6613-49eb-abea-b5dfd0e02dec"
    );
}

#[test]
fn bounded_input_is_accepted_at_the_limit_and_deduplicated_before_hashing() {
    let ips = vec!["10.9.8.7/24"; MAX_ALLOWED_IPS];
    assert_eq!(
        wg_input("nelomai-a", &ips)
            .reference_executable_guid()
            .to_string(),
        "9f77b43f-7149-4a48-8f33-80cf0de167f8"
    );
}
