use nelomai_client_api::RuntimeTarget;
use nelomai_client_container::host::RuntimeBootstrapV1;
use nelomai_contracts::RuntimeSlot;

fn bootstrap(namespaces: &[&str]) -> RuntimeBootstrapV1 {
    RuntimeBootstrapV1 {
        target: RuntimeTarget {
            container_version: "0.2.16".into(),
            runtime_version: "0.2.16".into(),
            runtime_contract_version: 1,
            runtime_slot: RuntimeSlot::Latest,
        },
        session_generation: None,
        incarnation: "synthetic-child".into(),
        data_root: "/synthetic/private".into(),
        runtime_namespaces: namespaces.iter().map(|value| (*value).into()).collect(),
        pending_slot: None,
    }
}

#[test]
fn child_bootstrap_never_opens_common_auth_or_unbound_runtime_namespaces() {
    for names in [
        vec!["auth-v1"],
        vec!["runtime/latest/state/../state-v1.json"],
        vec!["runtime/stable/state/0.2.15/state-v1.json"],
        vec![
            "runtime/latest/state/0.2.16/state-v1.json",
            "runtime/latest/state/0.2.16/state-v1.json",
        ],
    ] {
        assert!(bootstrap(&names).runtime_paths().is_err());
    }
}

#[test]
fn child_bootstrap_only_derives_paths_for_admitted_selected_and_retained_state() {
    let paths = bootstrap(&[
        "runtime/latest/state/0.2.16/state-v1.json",
        "runtime/stable/state/0.2.15/state-v1.json",
    ])
    .runtime_paths()
    .unwrap();
    assert_eq!(paths.len(), 2);
    assert_eq!(
        paths[0].namespace(),
        "runtime/latest/state/0.2.16/state-v1.json"
    );
    assert_eq!(
        paths[1].namespace(),
        "runtime/stable/state/0.2.15/state-v1.json"
    );
}
