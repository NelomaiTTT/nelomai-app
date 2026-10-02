//! Pure precreation GUID predictions, with no native calls or effect authority.
//!
//! Audited sources (including the entry points, not just the shared helper):
//! - AWG 575626d8f8aa5b64114cf378a08e54bf852d909b/main.go sets fixed=true;
//!   root deterministicguid.go/service.go hash the explicit service name.
//! - WG 4e6726c23ae9c5cb58e0c9910f3b7515621d133d/embeddable-dll-service/main.go
//!   sets fixed=true; tunnel/deterministicguid.go hashes the config basename.
//! - The local staging script pins/builds tunnel.dll, not wireguard.exe. The
//!   executable path cannot yield a member binding. Its independent algorithm
//!   reference lives exclusively in the cfg(test) module.
//!
//! Primary sources:
//! <https://github.com/amnezia-vpn/amneziawg-windows/blob/575626d8f8aa5b64114cf378a08e54bf852d909b/main.go>
//! <https://github.com/amnezia-vpn/amneziawg-windows/blob/575626d8f8aa5b64114cf378a08e54bf852d909b/deterministicguid.go>
//! <https://github.com/WireGuard/wireguard-windows/blob/4e6726c23ae9c5cb58e0c9910f3b7515621d133d/embeddable-dll-service/main.go>
//! <https://github.com/WireGuard/wireguard-windows/blob/4e6726c23ae9c5cb58e0c9910f3b7515621d133d/tunnel/deterministicguid.go>
//! All externally accepted member names are exact ASCII slot names: NFC is the
//! identity operation. GUIDs are the first 16 BLAKE2s-256 bytes interpreted as
//! Windows GUID memory; no RFC4122 version/variant rewriting is permitted.
//!
//! Validation here checks mathematical input scope, not installed signatures,
//! file handles, fresh absence, original-creator rights or native acceptance.
//! The composition owner must authenticate the actual provider and SAME name/
//! config inputs, and acquire the required native authority before effects.

use crate::member_carrier_native_ownership as receipt;
use blake2::{Blake2s256, Digest};
use nelomai_client_tunnel::TunnelTransport;
use nelomai_contracts::dispatcher::TunnelSlot;
use std::fmt;
use std::path::Path;

pub(crate) const AWG_SOURCE_REVISION: &str = "575626d8f8aa5b64114cf378a08e54bf852d909b";
pub(crate) const WG_SOURCE_REVISION: &str = "4e6726c23ae9c5cb58e0c9910f3b7515621d133d";
const MEMBER_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuidError {
    UnsupportedPath,
    UnsupportedRevision,
    UnsupportedName,
    InvalidConfigurationPath,
    ServiceNameMismatch,
}
pub(crate) type MemberSlot = TunnelSlot;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderPath {
    AmneziaSignedDll,
    WireGuardSignedDll,
    WireGuardExeInstallTunnelService,
    Unsupported,
}

/// Build factual member identity for the receipt Context, before native effects.
/// The caller must separately authenticate the actual runtime provider/revision
/// and the SAME configuration path/file and service invocation. Comparisons here
/// confer no source authentication, NEW-key ACK or original-creator authority.
/// No file read, resolution/canonicalization, registry access or name repair.
pub(crate) fn member_binding(
    provider: ProviderPath,
    provider_revision: &str,
    slot: TunnelSlot,
    configuration: &Path,
    service_name: &str,
) -> Result<receipt::Binding, GuidError> {
    let transport = validated_transport(provider, provider_revision)?;
    let filename = crate::redundancy::slot_config_filename(slot);
    let text = configuration
        .to_str()
        .ok_or(GuidError::InvalidConfigurationPath)?;
    // Path::file_name/components normalize some aliases such as trailing /.
    // Compare the raw spelling as well. Only ordinary absolute native paths are
    // supported; parent directories are independently validated by composition.
    if !configuration.is_absolute()
        || configuration.file_name().and_then(|s| s.to_str()) != Some(filename)
        || text.chars().any(|c| c.is_control() || c == '"')
        || text
            .split(std::path::is_separator)
            .enumerate()
            .any(|(i, part)| part == "." || part == ".." || (part.is_empty() && i != 0))
    {
        return Err(GuidError::InvalidConfigurationPath);
    }
    if service_name != crate::redundancy::slot_service_name(slot, transport) {
        return Err(GuidError::ServiceNameMismatch);
    }
    let native_name = slot_native_name(slot, transport)?;
    let guid = fixed_name_guid(native_name);
    Ok(receipt::Binding {
        role: match slot {
            TunnelSlot::A => receipt::Role::MemberA,
            TunnelSlot::B => receipt::Role::MemberB,
        },
        guid: guid.canonical_bytes(),
        name: native_name.into(),
        registry_path: format!("{MEMBER_INTERFACES}{}", guid.registry_component()),
    })
}

fn validated_transport(
    provider: ProviderPath,
    revision: &str,
) -> Result<TunnelTransport, GuidError> {
    let (transport, expected_revision) = match provider {
        ProviderPath::AmneziaSignedDll => (TunnelTransport::AmneziaWg3, AWG_SOURCE_REVISION),
        ProviderPath::WireGuardSignedDll => (TunnelTransport::WireGuard, WG_SOURCE_REVISION),
        ProviderPath::WireGuardExeInstallTunnelService | ProviderPath::Unsupported => {
            return Err(GuidError::UnsupportedPath);
        }
    };
    if revision != expected_revision {
        return Err(GuidError::UnsupportedRevision);
    }
    Ok(transport)
}

fn slot_native_name(
    slot: TunnelSlot,
    transport: TunnelTransport,
) -> Result<&'static str, GuidError> {
    match transport {
        TunnelTransport::WireGuard => crate::redundancy::slot_config_filename(slot)
            .strip_suffix(".conf")
            .ok_or(GuidError::InvalidConfigurationPath),
        TunnelTransport::AmneziaWg3 => Ok(crate::redundancy::slot_service_name(slot, transport)),
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedMember {
    path: ProviderPath,
    slot: MemberSlot,
    name: &'static str,
}
impl ValidatedMember {
    /// `revision` is a comparison input, NOT proof of a verified payload.
    /// No filesystem path, SCM name parsing, case folding or legacy fallback.
    pub(crate) fn new(
        path: ProviderPath,
        revision: &str,
        slot: MemberSlot,
        name: &str,
    ) -> Result<Self, GuidError> {
        let transport = validated_transport(path, revision)?;
        let expected_name = slot_native_name(slot, transport)?;
        if name != expected_name {
            return Err(GuidError::UnsupportedName);
        }
        Ok(Self {
            path,
            slot,
            name: expected_name,
        })
    }
    pub(crate) fn guid(self) -> NativeGuid {
        fixed_name_guid(self.name)
    }
    pub(crate) fn path(self) -> ProviderPath {
        self.path
    }
    pub(crate) fn slot(self) -> MemberSlot {
        self.slot
    }
    pub(crate) fn native_name(self) -> &'static str {
        self.name
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsGuidFields {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeGuid([u8; 16]);

impl NativeGuid {
    pub(crate) fn windows_memory_bytes(self) -> [u8; 16] {
        self.0
    }
    /// Canonical textual/network order, e.g. member ownership Binding.guid.
    /// This is NOT the memory supplied to Windows requested-GUID functions.
    pub(crate) fn canonical_bytes(self) -> [u8; 16] {
        let b = self.0;
        [
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13],
            b[14], b[15],
        ]
    }
    /// Field values for Windows GUID { Data1, Data2, Data3, Data4 }.
    pub(crate) fn windows_fields(self) -> WindowsGuidFields {
        let b = self.0;
        WindowsGuidFields {
            data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            data2: u16::from_le_bytes([b[4], b[5]]),
            data3: u16::from_le_bytes([b[6], b[7]]),
            data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
        }
    }
    /// Braced GUID component only; never a caller-selected registry root/path.
    pub(crate) fn registry_component(self) -> String {
        format!("{{{self}}}")
    }
}

impl fmt::Display for NativeGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

fn fixed_name_guid(name: &str) -> NativeGuid {
    let mut hash = Blake2s256::new();
    hash.update(b"Fixed WireGuard Windows GUID v1 jason@zx2c4.com");
    hash_string(&mut hash, name);
    finish_guid(hash)
}

// Only called on validated static ASCII names;
// private tests also use bounded ASCII recorded evidence names. No NFC guess.
fn hash_string(hash: &mut Blake2s256, text: &str) {
    hash.update(
        u32::try_from(text.len())
            .expect("validated GUID string length")
            .to_le_bytes(),
    );
    hash.update(text.as_bytes());
}

fn finish_guid(hash: Blake2s256) -> NativeGuid {
    let digest = hash.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    NativeGuid(bytes)
}

#[cfg(test)]
#[path = "member_native_guid_tests.rs"]
mod tests;
