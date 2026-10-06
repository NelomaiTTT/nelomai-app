//! Addressed SCM operations, accessible only via the authenticated engine's
//! inherited channel. Data routes/DNS belong to the session, not these services.
use crate::{tunnel_service_spec, ServiceError, ServiceSpec, ServiceStartMode};
use nelomai_client_tunnel::TunnelTransport;
use nelomai_contracts::dispatcher::{EnginePrimitive, TunnelSlot};
use std::path::Path;

// Ordinary AWG owns routes-state.json. The authenticated pair engine owns the
// member services' scoped routes and health instead; never attach the ordinary
// watchdog to those members. Only exact compiled service names can opt out.
#[cfg(any(windows, test))]
pub(crate) fn prepare_awg_route_supervision(
    service_name: &str,
    legacy: impl FnOnce() -> Result<(), ServiceError>,
) -> Result<(), ServiceError> {
    if service_name == crate::AMNEZIAWG_TUNNEL_SERVICE_NAME {
        legacy()
    } else if [TunnelSlot::A, TunnelSlot::B]
        .into_iter()
        .any(|slot| service_name == slot_service_name(slot, TunnelTransport::AmneziaWg3))
    {
        Ok(())
    } else {
        Err(ServiceError::InvalidRequest)
    }
}

/// Rendering only; the native parser still validates keys, addresses and AWG
/// parameters. A member must not independently change machine routes or DNS.
/// Secret-bearing output is zeroized, and errors never contain input lines.
pub fn slot_configuration(input: &str) -> Result<zeroize::Zeroizing<String>, ServiceError> {
    if input.len() > crate::MAX_FRAME_SIZE || input.contains('\0') {
        return Err(ServiceError::InvalidRequest);
    }
    let mut output = zeroize::Zeroizing::new(String::new());
    let mut section = 0;
    for raw in input.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case("[Interface]") && section == 0 {
            section = 1;
            output.push_str("[Interface]\nTable = off\n");
            continue;
        }
        if line.eq_ignore_ascii_case("[Peer]") && section == 1 {
            section = 2;
            output.push_str("[Peer]\n");
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(ServiceError::InvalidRequest)?;
        if section == 0 || value.trim().is_empty() {
            return Err(ServiceError::InvalidRequest);
        }
        let key = key.trim().to_ascii_lowercase();
        if matches!(
            key.as_str(),
            "preup" | "postup" | "predown" | "postdown" | "saveconfig"
        ) {
            return Err(ServiceError::InvalidRequest);
        }
        if section == 1 && matches!(key.as_str(), "dns" | "table" | "listenport") {
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    if section != 2 {
        return Err(ServiceError::InvalidRequest);
    }
    Ok(output)
}

/// Logical network intent is kept separate from addressless pair transports.
pub struct PairConfiguration {
    pub native: zeroize::Zeroizing<String>,
    pub addresses: Vec<ipnet::IpNet>,
    pub dns: Vec<std::net::IpAddr>,
}

impl PairConfiguration {
    pub fn matches_network(&self, other: &Self) -> bool {
        self.addresses == other.addresses && self.dns == other.dns
    }
}

/// Validates carrier network intent and renders one addressless member.
/// Native key/AWG value validation is still required before engine effects.
/// This does not enable a carrier factory or change the ordinary renderer.
pub fn pair_configuration(input: &str) -> Result<PairConfiguration, ServiceError> {
    let rendered = slot_configuration(input)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut section = 0;
    // Inspect logical fields before the member renderer discards DNS/Table.
    // Duplicate/unknown fields cannot acquire a different meaning on C/A/B.
    for raw in input.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = if line.eq_ignore_ascii_case("[Interface]") {
                1
            } else {
                2
            };
            continue;
        }
        let (key, _) = line.split_once('=').ok_or(ServiceError::InvalidRequest)?;
        let key = key.trim().to_ascii_lowercase();
        let supported = if section == 1 {
            matches!(
                key.as_str(),
                "privatekey"
                    | "address"
                    | "dns"
                    | "mtu"
                    | "table"
                    | "listenport"
                    | "headerprotectionkey"
                    | "contentpaddingaddition"
                    | "jc"
                    | "jmin"
                    | "jmax"
                    | "s1"
                    | "s2"
                    | "s3"
                    | "s4"
                    | "h1"
                    | "h2"
                    | "h3"
                    | "h4"
                    | "i1"
                    | "i2"
                    | "i3"
                    | "i4"
                    | "i5"
                    | "rekeyaftertime"
                    | "rekeytimeout"
                    | "rejectaftertime"
                    | "keepalivetimeout"
                    | "maxhandshakeattempts"
            )
        } else {
            matches!(
                key.as_str(),
                "publickey" | "presharedkey" | "allowedips" | "endpoint" | "persistentkeepalive"
            )
        };
        if !supported || !seen.insert((section, key)) {
            return Err(ServiceError::InvalidRequest);
        }
    }
    let parameters = crate::member_pair::MemberParameters::parse(input)
        .map_err(|_| ServiceError::InvalidRequest)?;
    let mut native = zeroize::Zeroizing::new(String::new());
    let mut addresses = Vec::new();
    let mut interface = false;
    for line in rendered.lines() {
        if line.starts_with('[') {
            interface = line.eq_ignore_ascii_case("[Interface]");
        }
        if interface {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim().eq_ignore_ascii_case("address") {
                    addresses = value
                        .split(',')
                        .map(|part| {
                            part.trim()
                                .parse()
                                .map_err(|_| ServiceError::InvalidRequest)
                        })
                        .collect::<Result<Vec<ipnet::IpNet>, _>>()?;
                    continue;
                }
            }
        }
        native.push_str(line);
        native.push('\n');
    }
    // IPv6 support is explicit and gated on the native carrier implementation;
    // rendering must not silently discard unsupported logical addresses.
    if addresses.len() != 1
        || !matches!(addresses[0], ipnet::IpNet::V4(a) if a.prefix_len() == 32 && usable_pair_v4(a.addr()))
        || parameters
            .allowed
            .iter()
            .any(|a| !matches!(a, ipnet::IpNet::V4(_)))
        || parameters
            .dns
            .iter()
            .any(|a| !matches!(a, std::net::IpAddr::V4(a) if usable_pair_v4(*a)))
        || parameters
            .dns
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != parameters.dns.len()
    {
        return Err(ServiceError::InvalidRequest);
    }
    Ok(PairConfiguration {
        native,
        addresses,
        dns: parameters.dns,
    })
}

fn usable_pair_v4(a: std::net::Ipv4Addr) -> bool {
    !a.is_unspecified()
        && !a.is_loopback()
        && !a.is_multicast()
        && !a.is_broadcast()
        && !a.is_link_local()
        && a.octets()[0] != 0
        && a.octets()[0] < 240
}

pub fn slot_config_filename(slot: TunnelSlot) -> &'static str {
    match slot {
        TunnelSlot::A => "nelomai-a.conf",
        TunnelSlot::B => "nelomai-b.conf",
    }
}

pub fn slot_service_name(slot: TunnelSlot, transport: TunnelTransport) -> &'static str {
    match (slot, transport) {
        (TunnelSlot::A, TunnelTransport::WireGuard) => "WireGuardTunnel$nelomai-a",
        (TunnelSlot::B, TunnelTransport::WireGuard) => "WireGuardTunnel$nelomai-b",
        (TunnelSlot::A, TunnelTransport::AmneziaWg3) => "NelomaiAmneziaWg3A",
        (TunnelSlot::B, TunnelTransport::AmneziaWg3) => "NelomaiAmneziaWg3B",
    }
}

pub fn slot_service_spec(
    executable: &Path,
    configuration: &Path,
    slot: TunnelSlot,
    transport: TunnelTransport,
) -> Result<ServiceSpec, ServiceError> {
    // WireGuard derives its interface AND SCM service name from the basename.
    if configuration.file_name().and_then(|s| s.to_str()) != Some(slot_config_filename(slot)) {
        return Err(ServiceError::UnsafePath);
    }
    let mut spec = tunnel_service_spec(executable, configuration, transport)?;
    spec.name = slot_service_name(slot, transport).into();
    spec.display_name = spec.name.clone();
    spec.start_mode = ServiceStartMode::OnDemand;
    if transport == TunnelTransport::AmneziaWg3 {
        spec.arguments[0] = "--amneziawg-slot-service".into();
        spec.arguments.push(
            match slot {
                TunnelSlot::A => "a",
                TunnelSlot::B => "b",
            }
            .into(),
        );
    }
    Ok(spec)
}

pub trait SlotServiceControl {
    type Error;
    fn stop(&mut self, slot: TunnelSlot, transport: TunnelTransport) -> Result<(), Self::Error>;
    fn start(&mut self, slot: TunnelSlot, transport: TunnelTransport) -> Result<(), Self::Error>;
    fn rebind(&mut self, slot: TunnelSlot, transport: TunnelTransport) -> Result<(), Self::Error>;
}

/// Returns false for legacy primitives so the original path handles them.
/// Start never performs implicit cleanup: the scoped owner checks both transport
/// names absent and journals Prepared first; native create fails if one exists.
/// Explicit StopSlot is owner-only cleanup after exact evidence validation; it
/// attempts both transports even if one fails. Never touches the sibling slot.
pub fn execute_slot_primitive<C: SlotServiceControl>(
    control: &mut C,
    action: EnginePrimitive,
) -> Result<bool, C::Error> {
    use EnginePrimitive::*;
    match action {
        StartWireguardSlot { slot } | StartAmneziawgSlot { slot } => {
            control.start(
                slot,
                if matches!(action, StartWireguardSlot { .. }) {
                    TunnelTransport::WireGuard
                } else {
                    TunnelTransport::AmneziaWg3
                },
            )?;
        }
        StopSlot { slot } => {
            let wg = control.stop(slot, TunnelTransport::WireGuard);
            let awg = control.stop(slot, TunnelTransport::AmneziaWg3);
            wg.and(awg)?;
        }
        RebindWireguardSlot { slot } | RebindAmneziawgSlot { slot } => {
            control.rebind(
                slot,
                if matches!(action, RebindWireguardSlot { .. }) {
                    TunnelTransport::WireGuard
                } else {
                    TunnelTransport::AmneziaWg3
                },
            )?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(test)]
mod route_supervision_tests {
    use super::*;
    #[test]
    fn member_start_does_not_require_legacy_route_journal() {
        for slot in [TunnelSlot::A, TunnelSlot::B] {
            prepare_awg_route_supervision(
                slot_service_name(slot, TunnelTransport::AmneziaWg3),
                || Err(ServiceError::Backend("endpoint_route_lost".into())),
            )
            .unwrap();
        }
    }
    #[test]
    fn ordinary_start_keeps_legacy_watchdog_failure() {
        let result = prepare_awg_route_supervision(crate::AMNEZIAWG_TUNNEL_SERVICE_NAME, || {
            Err(ServiceError::Backend("endpoint_route_lost".into()))
        });
        assert!(
            matches!(result, Err(ServiceError::Backend(ref code)) if code == "endpoint_route_lost")
        );
    }
    #[test]
    fn unknown_service_cannot_opt_out_of_supervision() {
        for name in [
            "foreign",
            "NelomaiAmneziaWg3A-other",
            "nelomaiamneziawg3a",
            "WireGuardTunnel$nelomai-a",
        ] {
            assert!(prepare_awg_route_supervision(name, || Ok(())).is_err());
        }
    }
}
