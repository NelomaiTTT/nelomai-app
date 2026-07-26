use std::{fs, path::PathBuf};

use nelomai_contracts::{
    BindPeerRequest, Bootstrap, ConnectionStart, ConnectionState, ErrorPayload,
    PeerBindingResponse, PeerOptions, ProbeResults, UpdateManifest,
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
    check::<ProbeResults>("valid/probe-results.json", "probe-results.schema.json");
    check::<ConnectionStart>(
        "valid/connection-start.json",
        "connection-start.schema.json",
    );
    check::<ConnectionState>(
        "valid/connection-state.json",
        "connection-state.schema.json",
    );
    check::<UpdateManifest>("valid/update-manifest.json", "update-manifest.schema.json");
    check::<ErrorPayload>("valid/error.json", "error.schema.json");
}

#[test]
fn unknown_optional_fields_are_ignored_by_an_older_client() {
    serde_json::from_str::<Bootstrap>(&fixture("compat/bootstrap-extra-optional.json")).unwrap();
}

#[test]
fn unknown_route_enum_is_rejected() {
    assert!(serde_json::from_str::<ConnectionStart>(&fixture(
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
