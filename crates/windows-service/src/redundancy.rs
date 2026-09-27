//! Addressed SCM operations, accessible only via the authenticated engine's
//! inherited channel. Data routes/DNS belong to the session, not these services.
use crate::{tunnel_service_spec, ServiceError, ServiceSpec, ServiceStartMode};
use nelomai_client_tunnel::TunnelTransport;
use nelomai_contracts::dispatcher::{EnginePrimitive, TunnelSlot};
use std::path::Path;

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
