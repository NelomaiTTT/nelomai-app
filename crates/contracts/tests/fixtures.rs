use std::{fs, path::PathBuf};

use nelomai_contracts::{
    BindPeerRequest, Bootstrap, ConnectionOperationResponse, ConnectionStartRequest,
    ConnectionStartResponse, ErrorPayload, PeerBindingResponse, PeerOptions, ProbeResults,
    ServerCandidatesResponse, ServerSelectionRequest, SplitTunnelApplyResult,
    SplitTunnelApplyStatus, SplitTunnelMode, SplitTunnelPolicy, SplitTunnelRevision,
    SplitTunnelSettingsUpdate, UpdateManifest,
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
