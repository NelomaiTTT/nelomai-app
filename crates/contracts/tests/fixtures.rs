use std::{fs, path::PathBuf};

use nelomai_contracts::{
    allows_new_connection_intent_operation, BindPeerRequest, Bootstrap, ConnectionIntentCapability,
    ConnectionIntentCapabilityResponse, ConnectionOperationResponse, ConnectionStartRequest,
    ConnectionStartResponse, EgressMode, ErrorPayload, OperationReconcileResponse, OperationState,
    PeerBindingResponse, PeerOptions, ProbeResults, ServerCandidatesResponse,
    ServerSelectionRequest, SplitTunnelApplyResult, SplitTunnelApplyStatus, SplitTunnelMode,
    SplitTunnelPolicy, SplitTunnelRevision, SplitTunnelSettingsUpdate, UpdateManifest,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

fn contracts_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts")
}

fn fixture(name: &str) -> String {
    fs::read_to_string(contracts_root().join("fixtures").join(name)).unwrap()
}

fn schema(name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(contracts_root().join("schemas").join(name)).unwrap())
        .unwrap()
}

fn schema_is_valid(schema_name: &str, value: &Value) -> bool {
    let common = jsonschema::Resource::from_contents(schema("common.schema.json")).unwrap();
    let validator = jsonschema::options()
        .with_resource(
            "https://nelomai.ru/schemas/client/v1/common.schema.json",
            common,
        )
        .build(&schema(schema_name))
        .unwrap();
    validator.is_valid(value)
}

fn check<T: DeserializeOwned>(fixture_name: &str, schema_name: &str) {
    let raw = fixture(fixture_name);
    let value: Value = serde_json::from_str(&raw).unwrap();
    assert!(
        schema_is_valid(schema_name, &value),
        "{fixture_name} failed schema"
    );
    serde_json::from_str::<T>(&raw).unwrap();
}

#[test]
fn shared_valid_fixtures_match_schemas_and_rust_types() {
    check::<Bootstrap>("valid/bootstrap.json", "bootstrap.schema.json");
    check::<PeerOptions>("valid/peer-options.json", "peer-options.schema.json");
    check::<PeerBindingResponse>("valid/peer-binding.json", "peer-binding.schema.json");
    check::<BindPeerRequest>(
        "valid/bind-peer-request.json",
        "bind-peer-request.schema.json",
    );
    check::<ServerSelectionRequest>("valid/probe-results.json", "probe-results.schema.json");
    check::<ProbeResults>("valid/probe-results.json", "probe-results.schema.json");
    check::<ServerCandidatesResponse>(
        "valid/server-candidates.json",
        "server-candidates.schema.json",
    );
    check::<ConnectionStartRequest>(
        "valid/connection-start.json",
        "connection-start.schema.json",
    );
    check::<ConnectionStartResponse>(
        "valid/connection-start-response.json",
        "connection-start-response.schema.json",
    );
    check::<ConnectionOperationResponse>(
        "valid/connection-operation.json",
        "connection-operation.schema.json",
    );
    check::<ErrorPayload>("valid/error.json", "error.schema.json");
    check::<UpdateManifest>("valid/update-manifest.json", "update-manifest.schema.json");
}

#[test]
fn probe_and_candidate_collections_reject_the_twenty_first_item() {
    let probe = serde_json::from_str::<Value>(&fixture("valid/probe-results.json")).unwrap()
        ["probes"][0]
        .clone();
    let candidate = serde_json::from_str::<Value>(&fixture("valid/server-candidates.json"))
        .unwrap()["candidates"][0]
        .clone();

    let mut probe_results =
        serde_json::from_str::<Value>(&fixture("valid/probe-results.json")).unwrap();
    probe_results["probes"] = Value::Array(vec![probe.clone(); 21]);
    assert!(!schema_is_valid(
        "probe-results.schema.json",
        &probe_results
    ));
    assert!(serde_json::from_value::<ProbeResults>(probe_results.clone()).is_err());
    assert!(serde_json::from_value::<ServerSelectionRequest>(probe_results).is_err());

    let mut start = serde_json::from_str::<Value>(&fixture("valid/connection-start.json")).unwrap();
    start["probes"] = Value::Array(vec![probe; 21]);
    assert!(!schema_is_valid("connection-start.schema.json", &start));
    assert!(serde_json::from_value::<ConnectionStartRequest>(start).is_err());
    let mut outgoing: ConnectionStartRequest =
        serde_json::from_str(&fixture("valid/connection-start.json")).unwrap();
    outgoing.probes = vec![outgoing.probes[0].clone(); 21];
    assert!(serde_json::to_value(outgoing).is_err());

    let mut candidates =
        serde_json::from_str::<Value>(&fixture("valid/server-candidates.json")).unwrap();
    candidates["candidates"] = Value::Array(vec![candidate; 21]);
    assert!(!schema_is_valid(
        "server-candidates.schema.json",
        &candidates
    ));
    assert!(serde_json::from_value::<ServerCandidatesResponse>(candidates).is_err());
}

#[test]
fn legacy_payloads_without_egress_mode_default_to_ipv4() {
    let binding_json =
        fixture("valid/peer-binding.json").replace(",\n    \"egress_mode\": \"prefer_ipv6\"", "");
    let binding: PeerBindingResponse = serde_json::from_str(&binding_json).unwrap();
    assert_eq!(binding.binding.unwrap().egress_mode, EgressMode::Ipv4);

    let start_json =
        fixture("valid/connection-start.json").replace(",\n  \"egress_mode\": \"ipv4\"", "");
    let start: ConnectionStartRequest = serde_json::from_str(&start_json).unwrap();
    assert_eq!(start.egress_mode, EgressMode::Ipv4);

    let response_json = fixture("valid/connection-start-response.json")
        .replace("    \"pool_id\": \"7\",\n", "")
        .replace(",\n    \"egress_mode\": \"ipv4\"", "");
    let response: ConnectionStartResponse = serde_json::from_str(&response_json).unwrap();
    assert_eq!(response.connection.egress_mode, EgressMode::Ipv4);
    assert_eq!(response.connection.pool_id, None);
}

#[test]
fn prefer_ipv6_serializes_as_the_panel_contract_value() {
    assert_eq!(
        serde_json::to_string(&EgressMode::PreferIpv6).unwrap(),
        "\"prefer_ipv6\""
    );
}

#[test]
fn unknown_optional_fields_are_ignored_by_an_older_client() {
    serde_json::from_str::<Bootstrap>(&fixture("compat/bootstrap-extra-optional.json")).unwrap();
}

#[test]
fn unknown_route_enum_is_rejected() {
    assert!(serde_json::from_str::<ConnectionStartRequest>(&fixture(
        "invalid/connection-start-unknown-route.json"
    ))
    .is_err());
}

#[test]
fn unknown_contract_version_is_rejected() {
    let raw =
        fixture("valid/bootstrap.json").replace("\"api_version\": \"1\"", "\"api_version\": \"2\"");
    assert!(serde_json::from_str::<Bootstrap>(&raw).is_err());
}

#[test]
fn common_error_payload_rejects_secret_fields() {
    let raw = fixture("invalid/error-with-config.json");
    assert!(serde_json::from_str::<ErrorPayload>(&raw).is_err());
    let value: Value = serde_json::from_str(&raw).unwrap();
    assert!(!schema_is_valid("error.schema.json", &value));
}

#[test]
fn connection_intent_fixtures_match_schema_and_tolerant_rust_types() {
    check::<ConnectionIntentCapabilityResponse>(
        "valid/connection-intent-capability.json",
        "connection-intent-capability.schema.json",
    );
    check::<OperationReconcileResponse>(
        "valid/connection-operation-reconcile.json",
        "connection-operation-reconcile.schema.json",
    );
    check::<ErrorPayload>(
        "valid/connection-operation-reconcile-conflict.json",
        "error.schema.json",
    );

    assert_eq!(
        serde_json::from_str::<OperationState>(r#""compensating""#).unwrap(),
        OperationState::Compensating,
    );
    let start: ConnectionStartRequest =
        serde_json::from_str(&fixture("valid/connection-start.json")).unwrap();
    assert!(!start.require_measured_selection);

    let bootstrap: Bootstrap = serde_json::from_str(&fixture("valid/bootstrap.json")).unwrap();
    assert!(bootstrap.capabilities.is_some());
}

#[test]
fn connection_intent_error_policy_is_complete_and_unambiguous() {
    let policy: Value =
        serde_json::from_str(&fixture("valid/connection-intent-error-policy.json")).unwrap();
    let cases = policy["cases"].as_array().unwrap();
    assert!(!cases.is_empty());

    let mut codes = std::collections::BTreeSet::new();
    for case in cases {
        assert!(codes.insert(case["code"].as_str().unwrap()));
        assert!(matches!(
            case["decision"].as_str().unwrap(),
            "retry_same_operation"
                | "retry_new_operation"
                | "retry_after"
                | "retry_once"
                | "reconcile_then_retry"
                | "reconcile_once"
                | "local_restart"
                | "terminal"
        ));
    }
    for required in [
        "connection_unavailable",
        "service_unavailable",
        "connection_stall_recycle_rate_limited",
        "operation_in_progress",
        "device_operation_busy",
        "operation_id_conflict",
        "ipv6_pool_unavailable",
    ] {
        assert!(codes.contains(required), "missing policy for {required}");
    }
    assert_eq!(policy["retry_after"]["minimum_seconds"], 1);
    assert_eq!(policy["retry_after"]["maximum_seconds"], 900);
    assert_eq!(policy["retry_after"]["fallback_seconds"], 300);
    assert_eq!(policy["unknown_decision"], "terminal");
}

#[test]
fn connection_intent_capability_requires_a_present_enabled_unexpired_snapshot() {
    let capability = ConnectionIntentCapability {
        revision: 1,
        expires_at: "2026-08-28T18:05:00Z".to_string(),
        connection_intent_recovery_v1: true,
    };
    assert!(allows_new_connection_intent_operation(
        Some(&capability),
        1_787_940_299,
    ));
    assert!(!allows_new_connection_intent_operation(
        Some(&capability),
        1_787_940_300,
    ));
    assert!(!allows_new_connection_intent_operation(None, 0));

    let disabled = ConnectionIntentCapability {
        connection_intent_recovery_v1: false,
        ..capability
    };
    assert!(!allows_new_connection_intent_operation(Some(&disabled), 0,));

    for revision in [0, -1] {
        let invalid = ConnectionIntentCapability {
            revision,
            expires_at: "2026-08-28T18:05:00Z".to_string(),
            connection_intent_recovery_v1: true,
        };
        assert!(!allows_new_connection_intent_operation(
            Some(&invalid),
            1_787_940_299,
        ));
    }
}

#[test]
fn connection_intent_capability_accepts_a_server_generation_revision() {
    let capability: ConnectionIntentCapability = serde_json::from_value(serde_json::json!({
        "revision": 1_787_940_300_000_i64,
        "expires_at": "2026-08-28T18:05:00Z",
        "connection_intent_recovery_v1": true
    }))
    .unwrap();

    assert_eq!(capability.revision, 1_787_940_300_000_i64);
}

#[test]
fn wireguard_configuration_is_redacted_from_debug_output() {
    let response: ConnectionStartResponse =
        serde_json::from_str(&fixture("valid/connection-start-response.json")).unwrap();
    let debug = format!("{response:?}");
    assert!(!debug.contains("delivered-only-to-core"));
    assert!(debug.contains("<redacted>"));

    let binding: PeerBindingResponse =
        serde_json::from_str(&fixture("valid/peer-binding.json")).unwrap();
    assert!(!format!("{binding:?}").contains("# client configuration"));
}

#[test]
fn split_tunnel_wire_types_match_panel_json() {
    let revision: SplitTunnelRevision =
        serde_json::from_str(&fixture("valid/split-tunnel-revision.json")).unwrap();
    assert!(revision.enabled);
    assert_eq!(revision.revision, 7);
    assert_eq!(revision.force_revision, 2);

    let policy: SplitTunnelPolicy =
        serde_json::from_str(&fixture("valid/split-tunnel-policy.json")).unwrap();
    assert_eq!(policy.format_version, 1);
    assert_eq!(policy.mode, SplitTunnelMode::ExcludeSelected);
    policy.validate_timestamps().unwrap();

    let settings: SplitTunnelSettingsUpdate =
        serde_json::from_str(&fixture("valid/split-tunnel-settings.json")).unwrap();
    assert_eq!(settings.mode, SplitTunnelMode::IncludeSelected);
    assert_eq!(settings.selected_packages.len(), 1);

    let apply: SplitTunnelApplyResult =
        serde_json::from_str(&fixture("valid/split-tunnel-apply-result.json")).unwrap();
    assert_eq!(apply.status, SplitTunnelApplyStatus::Applied);
    apply.validate_timestamps().unwrap();
}

#[test]
fn split_tunnel_enums_use_snake_case_and_payload_has_no_inventory() {
    assert_eq!(
        serde_json::to_string(&SplitTunnelMode::ExcludeSelected).unwrap(),
        "\"exclude_selected\""
    );
    assert_eq!(
        serde_json::to_string(&SplitTunnelApplyStatus::RolledBack).unwrap(),
        "\"rolled_back\""
    );

    let settings: SplitTunnelSettingsUpdate =
        serde_json::from_str(&fixture("valid/split-tunnel-settings.json")).unwrap();
    let serialized = serde_json::to_string(&settings).unwrap();
    assert!(!serialized.contains("icon"));
    assert!(!serialized.contains("inventory"));
    assert!(!serialized.contains("installed_packages"));
}

#[test]
fn split_tunnel_transport_parses_unknown_format_but_validates_timestamps() {
    let unknown = fixture("valid/split-tunnel-policy.json")
        .replace("\"format_version\": 1", "\"format_version\": 9");
    let policy: SplitTunnelPolicy = serde_json::from_str(&unknown).unwrap();
    assert_eq!(policy.format_version, 9);

    let invalid = fixture("valid/split-tunnel-policy.json")
        .replace("2026-07-30T12:00:00Z", "not-a-timestamp");
    let policy: SplitTunnelPolicy = serde_json::from_str(&invalid).unwrap();
    assert!(policy.validate_timestamps().is_err());

    let invalid_apply = fixture("valid/split-tunnel-apply-result.json")
        .replace("2026-07-30T12:01:00Z", "yesterday");
    let apply: SplitTunnelApplyResult = serde_json::from_str(&invalid_apply).unwrap();
    assert!(apply.validate_timestamps().is_err());
}

#[test]
fn split_tunnel_debug_omits_packages_names_and_cidrs() {
    let policy: SplitTunnelPolicy =
        serde_json::from_str(&fixture("valid/split-tunnel-policy.json")).unwrap();
    let policy_debug = format!("{policy:?}");
    assert!(policy_debug.contains("revision"));
    assert!(policy_debug.contains("selected_packages_count"));
    assert!(!policy_debug.contains("com.secret.application"));
    assert!(!policy_debug.contains("Яндекс"));
    assert!(!policy_debug.contains("203.0.113.0/24"));

    let settings: SplitTunnelSettingsUpdate =
        serde_json::from_str(&fixture("valid/split-tunnel-settings.json")).unwrap();
    let settings_debug = format!("{settings:?}");
    assert!(settings_debug.contains("selected_packages_count"));
    assert!(!settings_debug.contains("com.private.application"));
    assert!(!settings_debug.contains("Private App"));
}
