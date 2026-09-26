use nelomai_client_tunnel::TunnelTransport;
use nelomai_contracts::dispatcher::{EnginePrimitive, TunnelSlot};
use nelomai_windows_service::redundancy::slot_configuration;
use nelomai_windows_service::redundancy::{
    execute_slot_primitive, slot_config_filename, slot_service_name, slot_service_spec,
    SlotServiceControl,
};
use nelomai_windows_service::ServiceStartMode;
use std::path::Path;

#[derive(Default)]
struct Services {
    events: Vec<(String, TunnelSlot, TunnelTransport)>,
    fail_stop: bool,
}
impl SlotServiceControl for Services {
    type Error = &'static str;
    fn stop(&mut self, slot: TunnelSlot, transport: TunnelTransport) -> Result<(), Self::Error> {
        self.events.push(("stop".into(), slot, transport));
        if self.fail_stop {
            Err("busy")
        } else {
            Ok(())
        }
    }
    fn start(&mut self, slot: TunnelSlot, transport: TunnelTransport) -> Result<(), Self::Error> {
        self.events.push(("start".into(), slot, transport));
        Ok(())
    }
    fn rebind(&mut self, slot: TunnelSlot, transport: TunnelTransport) -> Result<(), Self::Error> {
        self.events.push(("rebind".into(), slot, transport));
        Ok(())
    }
}

#[test]
fn starting_b_only_replaces_b_services_never_a_or_global_resources() {
    let mut services = Services::default();
    execute_slot_primitive(
        &mut services,
        EnginePrimitive::StartAmneziawgSlot {
            slot: TunnelSlot::B,
        },
    )
    .unwrap();
    assert_eq!(
        services.events,
        vec![
            ("stop".into(), TunnelSlot::B, TunnelTransport::WireGuard),
            ("stop".into(), TunnelSlot::B, TunnelTransport::AmneziaWg3),
            ("start".into(), TunnelSlot::B, TunnelTransport::AmneziaWg3),
        ]
    );
}

#[test]
fn failed_slot_cleanup_prevents_new_service_creation() {
    let mut services = Services {
        fail_stop: true,
        ..Services::default()
    };
    assert!(execute_slot_primitive(
        &mut services,
        EnginePrimitive::StartWireguardSlot {
            slot: TunnelSlot::A
        }
    )
    .is_err());
    assert_eq!(services.events.len(), 1);
}

#[test]
fn stop_attempts_both_transports_even_if_first_fails() {
    let mut services = Services {
        fail_stop: true,
        ..Services::default()
    };
    assert!(execute_slot_primitive(
        &mut services,
        EnginePrimitive::StopSlot {
            slot: TunnelSlot::A
        }
    )
    .is_err());
    assert_eq!(services.events.len(), 2);
    assert!(services
        .events
        .iter()
        .all(|(op, slot, _)| op == "stop" && *slot == TunnelSlot::A));
}

#[test]
fn service_config_and_interface_names_are_disjoint_and_not_boot_started() {
    for (slot, file, wg, awg) in [
        (
            TunnelSlot::A,
            "nelomai-a.conf",
            "WireGuardTunnel$nelomai-a",
            "NelomaiAmneziaWg3A",
        ),
        (
            TunnelSlot::B,
            "nelomai-b.conf",
            "WireGuardTunnel$nelomai-b",
            "NelomaiAmneziaWg3B",
        ),
    ] {
        assert_eq!(slot_config_filename(slot), file);
        assert_eq!(slot_service_name(slot, TunnelTransport::WireGuard), wg);
        assert_eq!(slot_service_name(slot, TunnelTransport::AmneziaWg3), awg);
        for transport in [TunnelTransport::WireGuard, TunnelTransport::AmneziaWg3] {
            let config = Path::new("state").join(file);
            let spec =
                slot_service_spec(Path::new("engine.exe"), &config, slot, transport).unwrap();
            assert_eq!(spec.name, slot_service_name(slot, transport));
            assert_eq!(spec.start_mode, ServiceStartMode::OnDemand);
            assert!(spec.run_as_local_system && spec.unrestricted_service_sid);
            assert!(slot_service_spec(
                Path::new("engine.exe"),
                Path::new("nelomai.conf"),
                slot,
                transport
            )
            .is_err());
        }
    }
}

#[test]
fn slot_selector_is_closed_and_legacy_wire_format_is_unchanged() {
    assert_eq!(
        serde_json::to_string(&EnginePrimitive::StartWireguard).unwrap(),
        "\"start_wireguard\""
    );
    let value = serde_json::to_value(EnginePrimitive::StopSlot {
        slot: TunnelSlot::A,
    })
    .unwrap();
    assert_eq!(value, serde_json::json!({"stop_slot":{"slot":"a"}}));
    assert!(serde_json::from_value::<EnginePrimitive>(
        serde_json::json!({"stop_slot":{"slot":"../foreign"}})
    )
    .is_err());
    assert!(serde_json::from_value::<EnginePrimitive>(
        serde_json::json!({"stop_slot":{"slot":"a","service":"foreign"}})
    )
    .is_err());
}

#[test]
fn member_configuration_cannot_install_routes_dns_or_fixed_listen_port() {
    let input = "[Interface]\r\nPrivateKey = secret\r\nAddress = 10.90.0.2/32, fd00::2/128\r\nDNS = 10.90.0.1\r\nTable = auto\r\nListenPort = 51234\r\nHeaderProtectionKey = secret2\r\nContentPaddingAddition = 1\r\n[Peer]\r\nPublicKey = peer\r\nAllowedIPs = 0.0.0.0/0, ::/0\r\nEndpoint = 192.0.2.1:51820\r\n";
    let output = slot_configuration(input).unwrap();
    assert!(output.contains("Table = off\n"));
    assert!(!output.contains("DNS"));
    assert!(!output.contains("ListenPort"));
    assert!(!output.contains("auto"));
    assert!(output.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
    assert!(output.contains("HeaderProtectionKey = secret2"));
    assert!(output.contains("Address = 10.90.0.2/32, fd00::2/128"));
}

#[test]
fn member_configuration_rejects_ambiguous_structure_and_execution_hooks() {
    for input in [
        "[Peer]\nPublicKey=p",
        "[Interface]\n[Interface]\n[Peer]",
        "[Interface]\nPostUp = arbitrary\n[Peer]",
        "[Interface]\n[Peer]\n[Peer]",
        "[Interface]\nDNS\n[Peer]",
        "[Interface]\nPrivateKey=foo\0bar\n[Peer]",
    ] {
        assert!(slot_configuration(input).is_err());
    }
}
