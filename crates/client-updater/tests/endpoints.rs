use nelomai_client_updater::UpdateEndpointPolicy;
use url::Url;

#[test]
fn manifest_endpoint_contains_encoded_target_and_current_version() {
    let policy = UpdateEndpointPolicy::new("https://nelomai.ru").unwrap();

    assert_eq!(
        policy
            .manifest_url("darwin-aarch64-app", "0.1.0")
            .unwrap()
            .as_str(),
        "https://nelomai.ru/api/client/v1/updates/manifest/darwin-aarch64-app/0.1.0"
    );
}

#[test]
fn artifact_url_must_stay_on_the_authenticated_panel_update_path() {
    let policy = UpdateEndpointPolicy::new("https://nelomai.ru").unwrap();

    assert!(policy.is_trusted_artifact(
        &Url::parse(
            "https://nelomai.ru/api/client/v1/updates/artifacts/nelomai_0.2.0_aarch64.tar.gz"
        )
        .unwrap()
    ));
    assert!(!policy.is_trusted_artifact(
        &Url::parse("https://example.com/api/client/v1/updates/artifacts/stolen").unwrap()
    ));
    assert!(!policy.is_trusted_artifact(
        &Url::parse("https://nelomai.ru/api/client/v1/programs/download/other").unwrap()
    ));
    assert!(!policy.is_trusted_artifact(
        &Url::parse("https://user:password@nelomai.ru/api/client/v1/updates/artifacts/stolen")
            .unwrap()
    ));
}

#[test]
fn production_update_policy_requires_a_clean_https_origin() {
    assert!(UpdateEndpointPolicy::new("http://nelomai.ru").is_err());
    assert!(UpdateEndpointPolicy::new("https://user@nelomai.ru").is_err());
    assert!(UpdateEndpointPolicy::new("https://nelomai.ru/unexpected").is_err());
}
