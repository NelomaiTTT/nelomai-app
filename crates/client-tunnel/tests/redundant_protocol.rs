use nelomai_client_tunnel::redundancy::protocol::{Command, Member};
use nelomai_contracts::RuntimeSlot;
use serde_json::json;

fn start() -> serde_json::Value {
    json!({"action":"start","scope":{"runtime":"latest","runtime_generation":10,"session_id":"11111111-1111-4111-8111-111111111111","connection_generation":3},"primary":{"slot":"A","lease_id":"22222222-2222-4222-8222-222222222222","configuration":"[Interface]\nPrivateKey=SECRET\n[Peer]\n","probe":{"kind":"dns_a","target_ipv4":"10.0.0.1","query_name":"example.com","timeout_ms":2000}},"role_generation":1,"membership_generation":1,"warm_stop_v1":true,"options":{"excludedIpv4Cidrs":[],"excludeLocalNetworks":false,"policyHash":null}})
}

#[test]
fn primary_only_start_is_bounded_and_redacted() {
    let command: Command = serde_json::from_value(start()).unwrap();
    assert!(command.validate(RuntimeSlot::Latest).is_ok());
    assert!(command.validate(RuntimeSlot::Stable).is_err());
    assert!(!format!("{command:?}").contains("SECRET"));
    let wire = serde_json::to_value(&command).unwrap();
    assert_eq!(wire, start());
}
#[test]
fn malformed_scope_generations_probe_or_config_is_rejected() {
    for (path, value) in [
        ("/scope/session_id", json!("../foreign")),
        ("/role_generation", json!(-1)),
        ("/membership_generation", json!(-1)),
        ("/primary/lease_id", json!("bad")),
        ("/primary/configuration", json!("a\u{0000}b")),
        ("/primary/probe/timeout_ms", json!(1)),
        ("/primary/probe/target_ipv4", json!("127.0.0.1")),
    ] {
        let mut input = start();
        *input.pointer_mut(path).unwrap() = value;
        assert!(
            !serde_json::from_value::<Command>(input)
                .is_ok_and(|c| c.validate(RuntimeSlot::Latest).is_ok()),
            "{path}"
        );
    }
    let mut input = start();
    input["extra"] = json!(1);
    assert!(serde_json::from_value::<Command>(input).is_err());
}

#[test]
fn panel_initial_zero_generations_are_valid() {
    let mut value = start();
    value["role_generation"] = json!(0);
    value["membership_generation"] = json!(0);
    let command: Command = serde_json::from_value(value).unwrap();
    assert!(command.validate(RuntimeSlot::Latest).is_ok());
}

#[test]
fn prepare_recovery_stop_requires_exact_scope_and_nonzero_fences() {
    let wire = json!({"action":"prepare_recovery_stop", "scope":start()["scope"],
        "expected_revision":3,"expected_network_epoch":7});
    let command: Command = serde_json::from_value(wire.clone()).unwrap();
    assert!(command.validate(RuntimeSlot::Latest).is_ok());
    assert_eq!(serde_json::to_value(command).unwrap(), wire);
    for path in [
        "/expected_revision",
        "/expected_network_epoch",
        "/scope/connection_generation",
    ] {
        let mut invalid = wire.clone();
        *invalid.pointer_mut(path).unwrap() = 0.into();
        let command: Command = serde_json::from_value(invalid).unwrap();
        assert!(command.validate(RuntimeSlot::Latest).is_err());
    }
}
#[test]
fn configuration_has_its_own_limit_before_native_parser() {
    let mut input = start();
    input["primary"]["configuration"] = json!("x".repeat(1024 * 1024));
    assert!(serde_json::from_value::<Command>(input).is_err());
}
#[test]
fn debug_of_member_never_exposes_config() {
    let member: Member = serde_json::from_value(start()["primary"].clone()).unwrap();
    assert!(!format!("{member:?}").contains("SECRET"));
}

#[test]
fn prepare_stop_is_scope_only_validated_and_round_trips() {
    let wire = json!({"action":"prepare_stop", "scope":start()["scope"]});
    let command: Command = serde_json::from_value(wire.clone()).expect("scoped freeze command");
    command.validate(RuntimeSlot::Latest).unwrap();
    assert!(!command.is_start());
    assert_eq!(serde_json::to_value(&command).unwrap(), wire);
    assert!(command.validate(RuntimeSlot::Stable).is_err());
    let mut invalid = wire.clone();
    invalid["scope"]["connection_generation"] = json!(0);
    assert!(serde_json::from_value::<Command>(invalid)
        .unwrap()
        .validate(RuntimeSlot::Latest)
        .is_err());
    let mut extra = wire;
    extra["active"] = json!("B");
    assert!(serde_json::from_value::<Command>(extra).is_err());
}

#[test]
fn remove_standby_is_bounded_scoped_and_round_trips_without_configuration() {
    let wire = json!({"action":"remove_standby", "scope":start()["scope"], "slot":"B",
        "lease_id":"22222222-2222-4222-8222-222222222222", "expected_revision":2,
        "expected_network_epoch":1, "expected_membership_generation":0});
    let command: Command = serde_json::from_value(wire.clone()).unwrap();
    assert!(command.validate(RuntimeSlot::Latest).is_ok());
    assert!(!command.is_start());
    assert_eq!(serde_json::to_value(&command).unwrap(), wire);
    for (field, bad) in [
        ("lease_id", json!("../foreign")),
        ("expected_revision", json!(0)),
        ("expected_network_epoch", json!(0)),
        ("expected_membership_generation", json!(i64::MAX as u64 + 1)),
    ] {
        let mut value = wire.clone();
        value[field] = bad;
        assert!(serde_json::from_value::<Command>(value)
            .unwrap()
            .validate(RuntimeSlot::Latest)
            .is_err());
    }
}
