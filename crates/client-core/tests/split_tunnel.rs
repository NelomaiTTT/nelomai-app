mod support;
use async_trait::async_trait;
use nelomai_client_api::AccessSnapshot;
use nelomai_client_api::TokenResponse;
use nelomai_client_core::{
    split_tunnel_active, ClientCore, ConnectOptions, CoreApi, CoreApiError, CoreError,
    CoreLogEvent, CoreLogger, EffectiveSplitTunnelPolicy, Phase, PhysicalNetworkPollOutcome,
    SplitTunnelContext, SplitTunnelPolicyError, SplitTunnelSyncOutcome, StalledDataPlaneRecovery,
    StalledDataPlaneRecoveryOutcome,
};
use nelomai_client_storage::{
    MemorySplitTunnelStore, SecretStore, SplitTunnelStore, StorageError, StoredAuth,
    StoredSplitTunnelDomainResolution, StoredSplitTunnelState,
};
use nelomai_client_tunnel::{
    OwnedRedundantPolicyOutcome, OwnedRedundantPolicyRequest, QuickConnection, QuickReconnect,
    TunnelCapabilities, TunnelController, TunnelError, TunnelOptions, TunnelPlatform,
    TunnelStartRequest, TunnelStatus,
};
use nelomai_contracts::{
    Access, AccessState, ApiVersion, Bootstrap, BootstrapDefaults, Connection,
    ConnectionOperationRequest, ConnectionOperationResponse, ConnectionStartRequest,
    ConnectionStartResponse, Device, EgressMode, Layer, LeaseStatus, PeerBinding, Platform,
    RouteMode, SplitTunnelAddressRule, SplitTunnelAddressRuleKind, SplitTunnelAddressRuleScope,
    SplitTunnelApplyResult, SplitTunnelApplyStatus, SplitTunnelMode, SplitTunnelPolicy,
    SplitTunnelRevision, SplitTunnelSelectedPackage, SplitTunnelSettingsUpdate, TicConnectionMode,
    UpdateState,
};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tokio::sync::Notify;

#[test]
fn activation_rule_covers_platform_android_api_layer_and_route() {
    let cases = [
        (
            true,
            TunnelPlatform::Android,
            Some(32),
            Layer::Tic,
            RouteMode::ViaTak,
            false,
        ),
        (
            true,
            TunnelPlatform::Android,
            Some(33),
            Layer::Tic,
            RouteMode::ViaTak,
            true,
        ),
        (
            true,
            TunnelPlatform::Android,
            Some(35),
            Layer::Tic,
            RouteMode::Standalone,
            true,
        ),
        (
            true,
            TunnelPlatform::Android,
            Some(35),
            Layer::Stray,
            RouteMode::Standalone,
            true,
        ),
        (
            true,
            TunnelPlatform::Windows,
            None,
            Layer::Tic,
            RouteMode::ViaTak,
            true,
        ),
        (
            true,
            TunnelPlatform::Linux,
            None,
            Layer::Tic,
            RouteMode::Standalone,
            true,
        ),
        (
            true,
            TunnelPlatform::Macos,
            None,
            Layer::Stray,
            RouteMode::Standalone,
            true,
        ),
        (
            false,
            TunnelPlatform::Android,
            Some(35),
            Layer::Stray,
            RouteMode::Standalone,
            false,
        ),
    ];

    for (global_enabled, platform, api, layer, route_mode, expected) in cases {
        assert_eq!(
            split_tunnel_active(SplitTunnelContext {
                global_enabled,
                platform,
                android_api_level: api,
                layer,
                route_mode,
            }),
            expected
        );
    }
}

#[test]
fn android_24_through_32_keep_every_mode_as_an_ordinary_full_tunnel() {
    let policy = policy(SplitTunnelMode::IncludeSelected);
    for api in 24..=32 {
        for (layer, route_mode) in [
            (Layer::Tic, RouteMode::ViaTak),
            (Layer::Tic, RouteMode::Standalone),
            (Layer::Stray, RouteMode::Standalone),
        ] {
            let effective = EffectiveSplitTunnelPolicy::build(
                &policy,
                &[],
                capabilities(TunnelPlatform::Android, Some(api), true, true),
                layer,
                route_mode,
            )
            .unwrap();
            assert_eq!(effective.options, TunnelOptions::default());
        }
    }
}

#[test]
fn android_33_uses_split_for_every_connection_mode() {
    let policy = policy(SplitTunnelMode::ExcludeSelected);
    let installed = installed();
    let capabilities = capabilities(TunnelPlatform::Android, Some(33), true, true);

    let via_tak = EffectiveSplitTunnelPolicy::build(
        &policy,
        &installed,
        capabilities,
        Layer::Tic,
        RouteMode::ViaTak,
    )
    .unwrap();
    assert_eq!(
        via_tak.options.application_mode,
        Some(SplitTunnelMode::ExcludeSelected)
    );

    let stray = EffectiveSplitTunnelPolicy::build(
        &policy,
        &installed,
        capabilities,
        Layer::Stray,
        RouteMode::Standalone,
    )
    .unwrap();
    assert_eq!(
        stray.options.application_mode,
        Some(SplitTunnelMode::ExcludeSelected)
    );

    let standalone = EffectiveSplitTunnelPolicy::build(
        &policy,
        &installed,
        capabilities,
        Layer::Tic,
        RouteMode::Standalone,
    )
    .unwrap();
    assert_eq!(
        standalone.options.application_mode,
        Some(SplitTunnelMode::ExcludeSelected)
    );
}

#[test]
fn desktop_local_networks_always_stay_outside_the_tunnel() {
    let mut policy = policy(SplitTunnelMode::ExcludeSelected);
    policy.exclude_local_networks = false;

    for platform in [
        TunnelPlatform::Windows,
        TunnelPlatform::Linux,
        TunnelPlatform::Macos,
    ] {
        let effective = EffectiveSplitTunnelPolicy::build(
            &policy,
            &[],
            capabilities(platform, None, true, false),
            Layer::Tic,
            RouteMode::ViaTak,
        )
        .unwrap();
        assert!(effective.options.exclude_local_networks);
    }

    let android = EffectiveSplitTunnelPolicy::build(
        &policy,
        &installed(),
        capabilities(TunnelPlatform::Android, Some(35), true, true),
        Layer::Tic,
        RouteMode::ViaTak,
    )
    .unwrap();
    assert!(!android.options.exclude_local_networks);
}

#[test]
fn mandatory_precedence_suggestions_and_unavailable_history_are_preserved() {
    let mut policy = policy(SplitTunnelMode::ExcludeSelected);
    policy.mandatory_excluded_packages = vec!["com.example.bank".to_string()];
    policy.suggested_name_fragments = vec!["БАНК".to_string(), "янДеКс".to_string()];
    policy.selected_packages = vec![
        "com.example.bank".to_string(),
        "com.example.chat".to_string(),
        "com.example.unavailable".to_string(),
    ];
    let original_history = policy.selected_packages.clone();

    let effective = EffectiveSplitTunnelPolicy::build(
        &policy,
        &installed(),
        capabilities(TunnelPlatform::Android, Some(35), true, true),
        Layer::Tic,
        RouteMode::ViaTak,
    )
    .unwrap();

    assert_eq!(
        effective.options.package_ids,
        ["com.example.bank", "com.example.chat"]
    );
    assert_eq!(
        effective
            .suggested_packages
            .iter()
            .map(|package| package.package_id.as_str())
            .collect::<Vec<_>>(),
        ["com.yandex.maps"]
    );
    assert_eq!(
        effective.unavailable_selected_packages,
        ["com.example.unavailable"]
    );
    assert_eq!(policy.selected_packages, original_history);
}

#[test]
fn package_ids_use_the_unique_installed_spelling_when_case_differs() {
    let mut policy = policy(SplitTunnelMode::IncludeSelected);
    policy.mandatory_excluded_packages = vec!["com.example.bank".to_string()];
    policy.selected_packages = vec!["eu.livesport.flashscore_com".to_string()];
    let installed = vec![
        SplitTunnelSelectedPackage {
            package_id: "com.example.Bank".to_string(),
            display_name: "Bank".to_string(),
        },
        SplitTunnelSelectedPackage {
            package_id: "eu.livesport.FlashScore_com".to_string(),
            display_name: "Flashscore".to_string(),
        },
    ];

    let effective = EffectiveSplitTunnelPolicy::build(
        &policy,
        &installed,
        capabilities(TunnelPlatform::Android, Some(35), true, true),
        Layer::Tic,
        RouteMode::ViaTak,
    )
    .unwrap();

    assert_eq!(
        effective.options.package_ids,
        ["eu.livesport.FlashScore_com"]
    );
    assert!(effective.unavailable_selected_packages.is_empty());
}

#[test]
fn ambiguous_case_insensitive_package_match_is_never_applied() {
    let mut policy = policy(SplitTunnelMode::IncludeSelected);
    policy.selected_packages = vec!["com.example.FOO".to_string()];
    let installed = vec![
        SplitTunnelSelectedPackage {
            package_id: "com.example.Foo".to_string(),
            display_name: "First".to_string(),
        },
        SplitTunnelSelectedPackage {
            package_id: "com.example.foo".to_string(),
            display_name: "Second".to_string(),
        },
    ];

    let error = EffectiveSplitTunnelPolicy::build(
        &policy,
        &installed,
        capabilities(TunnelPlatform::Android, Some(35), true, true),
        Layer::Tic,
        RouteMode::ViaTak,
    )
    .unwrap_err();

    assert_eq!(error, SplitTunnelPolicyError::EmptyIncludeSelection);
}

#[test]
fn policy_collection_limits_are_rejected_before_application() {
    let cases = [
        (
            {
                let mut value = policy(SplitTunnelMode::ExcludeSelected);
                value.mandatory_excluded_packages = repeated("com.example.mandatory", 513);
                value
            },
            "split_tunnel_mandatory_packages_limit",
        ),
        (
            {
                let mut value = policy(SplitTunnelMode::ExcludeSelected);
                value.suggested_name_fragments = repeated("suggestion", 129);
                value
            },
            "split_tunnel_suggestions_limit",
        ),
        (
            {
                let mut value = policy(SplitTunnelMode::ExcludeSelected);
                value.selected_packages = repeated("com.example.selected", 513);
                value
            },
            "split_tunnel_selected_packages_limit",
        ),
        (
            {
                let mut value = policy(SplitTunnelMode::ExcludeSelected);
                value.excluded_ipv4_cidrs = repeated("203.0.113.0/24", 16_385);
                value
            },
            "split_tunnel_cidrs_limit",
        ),
    ];

    for (policy, code) in cases {
        let error = EffectiveSplitTunnelPolicy::build(
            &policy,
            &installed(),
            capabilities(TunnelPlatform::Android, Some(35), true, true),
            Layer::Tic,
            RouteMode::ViaTak,
        )
        .unwrap_err();
        assert_eq!(error.stable_code(), code);
    }
}

#[test]
fn malformed_package_ids_and_cidrs_are_rejected_before_use() {
    let cases = [
        (
            {
                let mut value = policy(SplitTunnelMode::ExcludeSelected);
                value.selected_packages = vec!["invalid".to_string()];
                value
            },
            "split_tunnel_invalid_package_id",
        ),
        (
            {
                let mut value = policy(SplitTunnelMode::ExcludeSelected);
                value.selected_packages =
                    vec!["com.example.app".to_string(), "com.example.app".to_string()];
                value
            },
            "split_tunnel_duplicate_package_id",
        ),
        (
            {
                let mut value = policy(SplitTunnelMode::ExcludeSelected);
                value.excluded_ipv4_cidrs = vec!["203.0.113.7/24".to_string()];
                value
            },
            "split_tunnel_noncanonical_ipv4_cidr",
        ),
        (
            {
                let mut value = policy(SplitTunnelMode::ExcludeSelected);
                value.excluded_ipv4_cidrs =
                    vec!["203.0.113.0/24".to_string(), "203.0.113.0/24".to_string()];
                value
            },
            "split_tunnel_duplicate_ipv4_cidr",
        ),
    ];

    for (policy, code) in cases {
        let error = EffectiveSplitTunnelPolicy::build(
            &policy,
            &installed(),
            capabilities(TunnelPlatform::Android, Some(35), true, true),
            Layer::Tic,
            RouteMode::ViaTak,
        )
        .unwrap_err();
        assert_eq!(error.stable_code(), code);
    }
}

#[test]
fn include_only_empty_selection_blocks_only_when_application_split_is_active() {
    let policy = policy(SplitTunnelMode::IncludeSelected);
    let active = EffectiveSplitTunnelPolicy::build(
        &policy,
        &[],
        capabilities(TunnelPlatform::Android, Some(35), true, true),
        Layer::Tic,
        RouteMode::ViaTak,
    )
    .unwrap_err();
    assert_eq!(active, SplitTunnelPolicyError::EmptyIncludeSelection);

    let inactive = EffectiveSplitTunnelPolicy::build(
        &policy,
        &[],
        capabilities(TunnelPlatform::Android, Some(32), true, true),
        Layer::Tic,
        RouteMode::ViaTak,
    )
    .unwrap();
    assert_eq!(inactive.options, TunnelOptions::default());

    let standalone = EffectiveSplitTunnelPolicy::build(
        &policy,
        &[],
        capabilities(TunnelPlatform::Android, Some(35), true, true),
        Layer::Tic,
        RouteMode::Standalone,
    )
    .unwrap_err();
    assert_eq!(standalone, SplitTunnelPolicyError::EmptyIncludeSelection);
}

#[test]
fn mandatory_packages_are_never_presented_as_include_choices() {
    let mut policy = policy(SplitTunnelMode::IncludeSelected);
    policy.mandatory_excluded_packages = vec!["com.example.bank".to_string()];
    policy.selected_packages = vec![
        "com.example.bank".to_string(),
        "com.example.chat".to_string(),
    ];

    let effective = EffectiveSplitTunnelPolicy::build(
        &policy,
        &installed(),
        capabilities(TunnelPlatform::Android, Some(35), true, true),
        Layer::Stray,
        RouteMode::Standalone,
    )
    .unwrap();
    assert_eq!(effective.options.package_ids, ["com.example.chat"]);
}

fn capabilities(
    platform: TunnelPlatform,
    android_api_level: Option<u32>,
    address_split_tunnel: bool,
    application_split_tunnel: bool,
) -> TunnelCapabilities {
    TunnelCapabilities {
        platform,
        android_api_level,
        address_split_tunnel,
        application_split_tunnel,
    }
}

fn policy(mode: SplitTunnelMode) -> SplitTunnelPolicy {
    SplitTunnelPolicy {
        format_version: 1,
        enabled: true,
        revision: 7,
        force_revision: 2,
        address_revision: 0,
        policy_hash: format!("sha256:{}", "a".repeat(64)),
        mode,
        exclude_local_networks: true,
        mandatory_excluded_packages: Vec::new(),
        suggested_name_fragments: Vec::new(),
        selected_packages: Vec::new(),
        excluded_ipv4_cidrs: vec!["203.0.113.0/24".to_string()],
        address_rules: Vec::new(),
        generated_at: "2026-07-30T12:00:00Z".to_string(),
    }
}

#[test]
fn ipv4_address_rule_is_added_as_a_direct_route() {
    let mut value = policy(SplitTunnelMode::ExcludeSelected);
    value.format_version = 2;
    value.address_revision = 1;
    value.address_rules = vec![SplitTunnelAddressRule {
        id: 1,
        scope: SplitTunnelAddressRuleScope::ThisDevice,
        kind: SplitTunnelAddressRuleKind::Ipv4,
        value: "198.51.100.42".to_string(),
    }];

    let effective = EffectiveSplitTunnelPolicy::build(
        &value,
        &[],
        capabilities(TunnelPlatform::Windows, None, true, false),
        Layer::Tic,
        RouteMode::ViaTak,
    )
    .unwrap();

    assert!(effective
        .options
        .excluded_ipv4_cidrs
        .contains(&"198.51.100.42/32".to_string()));
}

fn installed() -> Vec<SplitTunnelSelectedPackage> {
    vec![
        SplitTunnelSelectedPackage {
            package_id: "com.example.bank".to_string(),
            display_name: "Лучший Банк".to_string(),
        },
        SplitTunnelSelectedPackage {
            package_id: "com.example.chat".to_string(),
            display_name: "Chat".to_string(),
        },
        SplitTunnelSelectedPackage {
            package_id: "com.yandex.maps".to_string(),
            display_name: "Яндекс Карты".to_string(),
        },
    ]
}

fn repeated(value: &str, count: usize) -> Vec<String> {
    (0..count).map(|index| format!("{value}{index}")).collect()
}

#[tokio::test]
async fn coordinator_respects_revision_and_full_sync_intervals_without_operation_logs() {
    let fixture = coordinator_fixture(TunnelCapabilities {
        platform: TunnelPlatform::Android,
        android_api_level: Some(35),
        address_split_tunnel: true,
        application_split_tunnel: true,
    });

    assert!(matches!(
        fixture
            .core
            .synchronize_split_tunnel(1_000, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: false }
    ));
    assert_eq!(fixture.api.revision_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.api.policy_calls.load(Ordering::SeqCst), 1);

    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_299, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Skipped
    );
    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_300, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Unchanged
    );
    assert_eq!(fixture.api.revision_calls.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.api.policy_calls.load(Ordering::SeqCst), 1);

    assert!(matches!(
        fixture
            .core
            .synchronize_split_tunnel(87_400, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: false }
    ));
    assert_eq!(fixture.api.policy_calls.load(Ordering::SeqCst), 2);
    assert!(fixture.logger.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn force_revision_fetches_immediately_and_offline_cache_never_blocks() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture.api.set_revision(7, 3);
    fixture
        .core
        .synchronize_split_tunnel(1_300, false)
        .await
        .unwrap();
    assert_eq!(fixture.api.policy_calls.load(Ordering::SeqCst), 2);

    fixture.api.set_revision(7, 4);
    fixture.api.policy_online.store(false, Ordering::SeqCst);
    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_600, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::CachedOffline
    );
    assert_eq!(
        fixture.split_store.load().unwrap().last_seen_force_revision,
        3
    );

    fixture.api.policy_online.store(true, Ordering::SeqCst);
    assert!(matches!(
        fixture
            .core
            .synchronize_split_tunnel(1_900, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: false }
    ));
    assert_eq!(
        fixture.split_store.load().unwrap().last_seen_force_revision,
        4
    );

    fixture.api.online.store(false, Ordering::SeqCst);
    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(2_200, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::CachedOffline
    );
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_cached_offline")
    );
    assert!(fixture.split_store.load().unwrap().cached_policy.is_some());
}

#[tokio::test]
async fn policy_restart_preserves_dns46_connection_metadata() {
    check_policy_restart_metadata(false).await;
}

#[tokio::test]
async fn native_owned_pair_policy_does_not_require_legacy_saved_configuration() {
    for layer in [Layer::Tic, Layer::Stray] {
        let (fixture, running) = native_owned_policy_fixture(layer).await;
        let mut changed = policy(SplitTunnelMode::ExcludeSelected);
        changed.revision = 9;
        changed.policy_hash = format!("sha256:{}", "b".repeat(64));
        changed.exclude_local_networks = false;
        fixture.api.set_policy(changed.clone());
        fixture.api.set_revision(9, changed.force_revision);
        assert_eq!(
            fixture
                .core
                .synchronize_split_tunnel(1_100, true)
                .await
                .unwrap(),
            SplitTunnelSyncOutcome::Updated { reconnected: true }
        );
        assert_eq!(fixture.core.state().await.connection, Some(running.clone()));
        assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.tunnel.restart_starts.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.split_store.load().unwrap().working_policy_hash,
            Some(changed.policy_hash)
        );
        assert_eq!(
            fixture
                .api
                .apply_results
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .status,
            SplitTunnelApplyStatus::Applied
        );
        let requests = fixture.tunnel.owned_policy_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].session_id,
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(requests[0].connection.lease_id, running.lease_id);
        assert_eq!(requests[0].connection.layer, layer);
        assert_eq!(requests[0].connection.egress_mode, running.egress_mode);
        assert!(!requests[0].connection.allow_alternate);
        assert!(!requests[0].options.exclude_local_networks);
    }
}

async fn native_owned_policy_fixture(layer: Layer) -> (CoordinatorFixture, Connection) {
    let fixture = coordinator_fixture(android_35_capabilities());
    let initial = policy(SplitTunnelMode::ExcludeSelected);
    fixture
        .split_store
        .save(&StoredSplitTunnelState {
            cached_policy: Some(initial.clone()),
            previous_working_policy: Some(initial.clone()),
            working_policy_hash: Some(initial.policy_hash.clone()),
            ..StoredSplitTunnelState::default()
        })
        .unwrap();
    let running = Connection {
        lease_id: "11111111-1111-4111-8111-111111111111".into(),
        session_id: Some("22222222-2222-4222-8222-222222222222".into()),
        pool_id: None,
        layer,
        transport_protocol: Default::default(),
        tic_connection_mode: TicConnectionMode::Dynamic,
        route_mode: if layer == Layer::Tic {
            RouteMode::ViaTak
        } else {
            RouteMode::Standalone
        },
        egress_mode: if layer == Layer::Tic {
            EgressMode::PreferIpv6
        } else {
            EgressMode::Ipv4
        },
        probe_url: None,
        status: LeaseStatus::Connected,
        pinned: false,
        stopped_at: None,
    };
    fixture.api.set_bootstrap_connection(running.clone());
    fixture
        .tunnel
        .independent_native_owner
        .store(true, Ordering::SeqCst);
    *fixture.tunnel.owned_session_scope.lock().unwrap() = running.session_id.clone();
    *fixture.tunnel.status.lock().unwrap() = TunnelStatus::Running;
    fixture.core.bootstrap(1_000).await.unwrap();
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert!(fixture
        .secret_store
        .load()
        .unwrap()
        .unwrap()
        .saved_connection
        .is_none());
    (fixture, running)
}

#[tokio::test]
async fn native_owned_pair_unchanged_policy_is_confirmed_without_reconnect() {
    let (fixture, running) = native_owned_policy_fixture(Layer::Tic).await;
    fixture
        .tunnel
        .owned_policy_outcomes
        .lock()
        .unwrap()
        .push_back(Ok(OwnedRedundantPolicyOutcome::Unchanged));
    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_100, true)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: false }
    );
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::Applied
    );
    assert_eq!(fixture.core.state().await.connection, Some(running));
    assert_eq!(
        fixture.tunnel.owned_policy_requests.lock().unwrap().len(),
        1
    );
    assert_eq!(fixture.tunnel.restart_starts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_owned_pair_policy_does_not_probe_legacy_physical_network() {
    let (fixture, _) = native_owned_policy_fixture(Layer::Tic).await;
    fixture
        .tunnel
        .block_fingerprint
        .store(true, Ordering::SeqCst);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        fixture.core.synchronize_split_tunnel(1_100, true),
    )
    .await;
    assert!(
        result.is_ok(),
        "the native session owns network tracking; policy apply must not wait for a legacy probe"
    );
    assert!(result.unwrap().is_ok());
    assert_eq!(fixture.tunnel.fingerprint_calls.load(Ordering::SeqCst), 0);
    assert!(fixture
        .split_store
        .load()
        .unwrap()
        .applied_physical_network_fingerprint
        .is_none());
}

#[tokio::test]
async fn native_owned_pair_periodic_network_poll_does_not_enter_legacy_recovery() {
    for has_session_scope in [true, false] {
        let (fixture, mut connection) = native_owned_policy_fixture(Layer::Tic).await;
        if !has_session_scope {
            connection.session_id = None;
            fixture.api.set_bootstrap_connection(connection);
            fixture.core.bootstrap(1_010).await.unwrap();
        }
        fixture
            .tunnel
            .block_fingerprint
            .store(true, Ordering::SeqCst);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            fixture.core.poll_physical_network(1_100),
        )
        .await;
        assert!(
            result.is_ok(),
            "native-owned sessions have their own network monitor"
        );
        assert_eq!(
            result.unwrap().unwrap(),
            PhysicalNetworkPollOutcome::Skipped
        );
        assert_eq!(fixture.tunnel.fingerprint_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.tunnel.restart_starts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn native_owned_pair_rollback_keeps_old_policy_without_legacy_restart() {
    let (fixture, running) = native_owned_policy_fixture(Layer::Tic).await;
    let mut changed = policy(SplitTunnelMode::ExcludeSelected);
    changed.policy_hash = format!("sha256:{}", "b".repeat(64));
    changed.exclude_local_networks = false;
    fixture.api.set_policy(changed);
    fixture
        .tunnel
        .owned_policy_outcomes
        .lock()
        .unwrap()
        .push_back(Ok(OwnedRedundantPolicyOutcome::RolledBack));
    let result = fixture
        .core
        .save_split_tunnel_settings(
            &SplitTunnelSettingsUpdate {
                mode: SplitTunnelMode::ExcludeSelected,
                exclude_local_networks: false,
                selected_packages: Vec::new(),
            },
            1_100,
        )
        .await;
    assert!(
        matches!(result, Err(CoreError::SplitTunnel(code)) if code == "split_tunnel_apply_failed")
    );
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(fixture.core.state().await.connection, Some(running));
    assert_eq!(
        fixture.split_store.load().unwrap().working_policy_hash,
        Some(format!("sha256:{}", "a".repeat(64)))
    );
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::RolledBack
    );
    assert_eq!(
        fixture.tunnel.owned_policy_requests.lock().unwrap().len(),
        1
    );
    assert_eq!(fixture.tunnel.restart_starts.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_owned_pair_double_failure_does_not_publish_connected() {
    let (fixture, _) = native_owned_policy_fixture(Layer::Tic).await;
    fixture
        .tunnel
        .owned_policy_outcomes
        .lock()
        .unwrap()
        .push_back(Ok(OwnedRedundantPolicyOutcome::Failed));
    fixture
        .core
        .synchronize_split_tunnel(1_100, true)
        .await
        .unwrap();
    assert_eq!(fixture.core.state().await.phase, Phase::Stopping);
    assert_eq!(
        fixture.tunnel.status().await.unwrap(),
        TunnelStatus::Stopped
    );
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::Failed
    );
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_rollback_failed")
    );
    assert_eq!(fixture.tunnel.restart_starts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_owned_pair_admission_error_preserves_live_transport() {
    let (fixture, running) = native_owned_policy_fixture(Layer::Tic).await;
    fixture
        .tunnel
        .owned_policy_outcomes
        .lock()
        .unwrap()
        .push_back(Err("native_policy_owner_changed"));
    fixture
        .core
        .synchronize_split_tunnel(1_100, true)
        .await
        .unwrap();
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(fixture.core.state().await.connection, Some(running));
    assert_eq!(
        fixture.tunnel.status().await.unwrap(),
        TunnelStatus::Running
    );
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.tunnel.restart_starts.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::Failed
    );
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_apply_failed")
    );
}

#[tokio::test]
async fn native_owned_pair_busy_keeps_cached_policy_without_hour_penalty_or_false_apply_report() {
    let (fixture, running) = native_owned_policy_fixture(Layer::Stray).await;
    let old_hash = fixture.split_store.load().unwrap().working_policy_hash;
    let mut changed = policy(SplitTunnelMode::ExcludeSelected);
    changed.revision = 9;
    changed.policy_hash = format!("sha256:{}", "b".repeat(64));
    changed.exclude_local_networks = false;
    fixture.api.set_policy(changed.clone());
    fixture
        .api
        .set_revision(changed.revision, changed.force_revision);
    fixture
        .tunnel
        .owned_policy_outcomes
        .lock()
        .unwrap()
        .push_back(Err("redundant_policy_busy"));

    fixture
        .core
        .synchronize_split_tunnel(1_100, true)
        .await
        .unwrap();

    let stored = fixture.split_store.load().unwrap();
    assert_eq!(stored.working_policy_hash, None);
    assert_eq!(
        stored.previous_working_policy.map(|p| p.policy_hash),
        old_hash
    );
    assert_eq!(
        stored.cached_policy.unwrap().policy_hash,
        changed.policy_hash
    );
    assert_eq!(stored.failed_policy_hash, None);
    assert_eq!(stored.failed_policy_retry_after_unix, None);
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_apply_busy")
    );
    assert!(fixture.api.apply_results.lock().unwrap().is_empty());
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(fixture.core.state().await.connection, Some(running.clone()));
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.tunnel.restart_starts.load(Ordering::SeqCst), 0);

    // Existing revision polling, not a new timer/queue, retries once the owner is free.
    fixture
        .core
        .synchronize_split_tunnel(1_401, false)
        .await
        .unwrap();
    assert_eq!(
        fixture.tunnel.owned_policy_requests.lock().unwrap().len(),
        2
    );
    assert_eq!(
        fixture.split_store.load().unwrap().working_policy_hash,
        Some(changed.policy_hash)
    );
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::Applied
    );
    assert_eq!(fixture.core.state().await.connection, Some(running));
}

#[tokio::test]
async fn native_owned_pair_busy_reply_cannot_claim_a_stopped_transport_is_connected() {
    for status in [TunnelStatus::Stopped, TunnelStatus::Failed] {
        let (fixture, _) = native_owned_policy_fixture(Layer::Stray).await;
        *fixture.tunnel.status.lock().unwrap() = status;
        fixture
            .tunnel
            .owned_policy_outcomes
            .lock()
            .unwrap()
            .push_back(Err("redundant_policy_busy"));
        fixture
            .core
            .synchronize_split_tunnel(1_100, true)
            .await
            .unwrap();
        assert_eq!(fixture.core.state().await.phase, Phase::Stopping);
        assert_eq!(
            fixture.core.split_tunnel_warning().await.as_deref(),
            Some("split_tunnel_apply_busy")
        );
        assert!(fixture.api.apply_results.lock().unwrap().is_empty());
        assert_eq!(fixture.split_store.load().unwrap().failed_policy_hash, None);
    }
}

#[tokio::test]
async fn native_owned_pair_busy_with_matching_hash_remains_pending_for_existing_poll() {
    for code in ["redundant_policy_busy", "tunnel_operation_in_progress"] {
        let (fixture, running) = native_owned_policy_fixture(Layer::Stray).await;
        let initial = fixture.split_store.load().unwrap().cached_policy.unwrap();
        fixture
            .tunnel
            .owned_policy_outcomes
            .lock()
            .unwrap()
            .push_back(Err(code));
        fixture
            .core
            .synchronize_split_tunnel(1_100, true)
            .await
            .unwrap();
        let pending = fixture.split_store.load().unwrap();
        assert_eq!(
            pending.cached_policy.unwrap().policy_hash,
            initial.policy_hash
        );
        assert_eq!(pending.working_policy_hash, None);
        assert_eq!(
            pending.previous_working_policy.unwrap().policy_hash,
            initial.policy_hash
        );
        assert_eq!(pending.failed_policy_hash, None);
        assert!(fixture.api.apply_results.lock().unwrap().is_empty());

        fixture
            .core
            .synchronize_split_tunnel(1_401, false)
            .await
            .unwrap();
        assert_eq!(
            fixture.tunnel.owned_policy_requests.lock().unwrap().len(),
            2
        );
        assert_eq!(
            fixture.split_store.load().unwrap().working_policy_hash,
            Some(initial.policy_hash)
        );
        assert_eq!(fixture.core.state().await.connection, Some(running));
    }
}

#[tokio::test]
async fn native_owned_pair_busy_status_rpc_failure_is_not_a_failed_policy() {
    let (fixture, _) = native_owned_policy_fixture(Layer::Stray).await;
    fixture
        .tunnel
        .owned_policy_outcomes
        .lock()
        .unwrap()
        .push_back(Err("redundant_policy_busy"));
    fixture
        .tunnel
        .fail_next_status
        .store(true, Ordering::SeqCst);
    fixture
        .core
        .synchronize_split_tunnel(1_100, true)
        .await
        .unwrap();
    assert!(!fixture.tunnel.fail_next_status.load(Ordering::SeqCst));
    let pending = fixture.split_store.load().unwrap();
    assert_eq!(pending.failed_policy_hash, None);
    assert_eq!(pending.failed_policy_retry_after_unix, None);
    assert_eq!(pending.working_policy_hash, None);
    assert!(fixture.api.apply_results.lock().unwrap().is_empty());
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_apply_busy")
    );
    assert_eq!(fixture.core.state().await.phase, Phase::Stopping);
}

#[tokio::test]
async fn native_owned_pair_busy_then_rollback_keeps_previous_policy_for_next_start() {
    let (fixture, running) = native_owned_policy_fixture(Layer::Stray).await;
    let previous = fixture.split_store.load().unwrap().cached_policy.unwrap();
    let mut changed = previous.clone();
    changed.revision = 9;
    changed.policy_hash = format!("sha256:{}", "b".repeat(64));
    changed.exclude_local_networks = false;
    fixture.api.set_policy(changed.clone());
    fixture
        .api
        .set_revision(changed.revision, changed.force_revision);
    fixture
        .tunnel
        .owned_policy_outcomes
        .lock()
        .unwrap()
        .extend([
            Err("redundant_policy_busy"),
            Ok(OwnedRedundantPolicyOutcome::RolledBack),
        ]);
    fixture
        .core
        .synchronize_split_tunnel(1_100, true)
        .await
        .unwrap();
    fixture
        .core
        .synchronize_split_tunnel(1_401, false)
        .await
        .unwrap();
    let stored = fixture.split_store.load().unwrap();
    assert_eq!(
        stored.working_policy_hash, None,
        "rollback must not invent native confirmation"
    );
    assert_eq!(stored.failed_policy_hash, Some(changed.policy_hash));
    assert_eq!(
        stored.previous_working_policy.unwrap().policy_hash,
        previous.policy_hash
    );

    let next = fixture
        .core
        .connection_intent_tunnel_options(running.layer, running.route_mode, 1_402)
        .await
        .unwrap();
    assert_eq!(next.policy_hash, Some(previous.policy_hash));
    assert_eq!(next.exclude_local_networks, previous.exclude_local_networks);
    assert_eq!(fixture.core.state().await.connection, Some(running));
}

#[tokio::test]
async fn native_owned_pair_late_policy_reply_cannot_revive_stop_or_owner_eof() {
    for owner_eof in [false, true] {
        let (fixture, _) = native_owned_policy_fixture(Layer::Tic).await;
        let fixture = Arc::new(fixture);
        fixture
            .tunnel
            .block_owned_policy
            .store(true, Ordering::SeqCst);
        let apply = tokio::spawn({
            let fixture = fixture.clone();
            async move { fixture.core.synchronize_split_tunnel(1_100, true).await }
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            fixture.tunnel.owned_policy_entered.notified(),
        )
        .await
        .unwrap();
        if owner_eof {
            fixture.local.stop_local_on_disconnect().await.unwrap();
        } else {
            fixture.core.signal_start_cancellation();
        }
        let auth_after_cancel = fixture.secret_store.load().unwrap();
        fixture.tunnel.owned_policy_release.notify_one();
        assert!(matches!(
            apply.await.unwrap(),
            Err(CoreError::StartCancelled)
        ));
        if owner_eof {
            assert_eq!(fixture.core.state().await.phase, Phase::Error);
            assert!(fixture.core.state().await.connection.is_none());
        } else {
            fixture.core.stop_locally().await.unwrap();
            assert_eq!(fixture.core.state().await.phase, Phase::Stopping);
        }
        assert_eq!(
            fixture.tunnel.status().await.unwrap(),
            TunnelStatus::Stopped
        );
        if owner_eof {
            assert_eq!(fixture.secret_store.load().unwrap(), auth_after_cancel);
        }
        assert!(fixture.api.apply_results.lock().unwrap().is_empty());
        assert_eq!(fixture.tunnel.restart_starts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn native_owned_pair_without_session_scope_never_falls_back_to_legacy() {
    let (fixture, mut running) = native_owned_policy_fixture(Layer::Tic).await;
    running.session_id = None;
    fixture.api.set_bootstrap_connection(running.clone());
    fixture.core.bootstrap(1_010).await.unwrap();
    fixture
        .core
        .synchronize_split_tunnel(1_100, true)
        .await
        .unwrap();
    assert_eq!(fixture.core.state().await.connection, Some(running));
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_saved_connection_unavailable")
    );
    assert!(fixture
        .tunnel
        .owned_policy_requests
        .lock()
        .unwrap()
        .is_empty());
    assert_eq!(fixture.tunnel.restart_starts.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_owned_pair_late_policy_reply_preserves_new_session_observation() {
    let (fixture, mut observed) = native_owned_policy_fixture(Layer::Tic).await;
    let fixture = Arc::new(fixture);
    fixture
        .tunnel
        .block_owned_policy
        .store(true, Ordering::SeqCst);
    let apply = tokio::spawn({
        let fixture = fixture.clone();
        async move { fixture.core.synchronize_split_tunnel(1_100, true).await }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        fixture.tunnel.owned_policy_entered.notified(),
    )
    .await
    .unwrap();
    observed.session_id = Some("33333333-3333-4333-8333-333333333333".into());
    let bootstrap = bootstrap_observation_while_recovery_pending(&fixture, observed.clone()).await;
    fixture.tunnel.owned_policy_release.notify_one();
    assert!(matches!(
        apply.await.unwrap(),
        Err(CoreError::StartCancelled)
    ));
    bootstrap.await.unwrap().unwrap();
    assert_eq!(fixture.core.state().await.connection, Some(observed));
    assert_eq!(
        fixture.tunnel.stops.load(Ordering::SeqCst),
        0,
        "a different native session must not be stopped as compensation for this retired policy"
    );
    assert!(fixture.api.apply_results.lock().unwrap().is_empty());
}

#[tokio::test]
async fn native_owned_pair_cancelled_reply_preserves_independent_handoff() {
    for owner_eof in [false, true] {
        let (fixture, _) = native_owned_policy_fixture(Layer::Tic).await;
        let fixture = Arc::new(fixture);
        fixture
            .tunnel
            .block_owned_policy
            .store(true, Ordering::SeqCst);
        let apply = tokio::spawn({
            let fixture = fixture.clone();
            async move { fixture.core.synchronize_split_tunnel(1_100, true).await }
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            fixture.tunnel.owned_policy_entered.notified(),
        )
        .await
        .unwrap();
        if owner_eof {
            fixture.local.stop_local_on_disconnect().await.unwrap();
        } else {
            fixture.local.stop_local_for_transition().await.unwrap();
        }
        let stops = fixture.tunnel.stops.load(Ordering::SeqCst);
        // Another native owner has already started after S1's scoped close.
        // S1's completed response is still waiting for delivery to its old Core.
        *fixture.tunnel.owned_session_scope.lock().unwrap() =
            Some("33333333-3333-4333-8333-333333333333".into());
        *fixture.tunnel.status.lock().unwrap() = TunnelStatus::Running;
        fixture.tunnel.owned_policy_release.notify_one();
        assert!(matches!(
            apply.await.unwrap(),
            Err(CoreError::StartCancelled)
        ));
        assert_eq!(
            fixture.tunnel.stops.load(Ordering::SeqCst),
            stops,
            "a cancelled owned-policy reply must never issue global Stop against S2"
        );
        assert_eq!(
            fixture.tunnel.status().await.unwrap(),
            TunnelStatus::Running
        );
        assert_eq!(
            fixture
                .tunnel
                .owned_session_scope
                .lock()
                .unwrap()
                .as_deref(),
            Some("33333333-3333-4333-8333-333333333333")
        );
        assert_eq!(
            fixture.core.state().await.phase,
            if owner_eof {
                Phase::Error
            } else {
                Phase::Ready
            }
        );
    }
}

#[tokio::test]
async fn native_owned_pair_retired_terminal_reply_preserves_new_recovery_recipe() {
    for outcome in [
        OwnedRedundantPolicyOutcome::RolledBack,
        OwnedRedundantPolicyOutcome::Failed,
    ] {
        let (fixture, mut observed) = native_owned_policy_fixture(Layer::Tic).await;
        let fixture = Arc::new(fixture);
        fixture
            .tunnel
            .owned_policy_outcomes
            .lock()
            .unwrap()
            .push_back(Ok(outcome));
        fixture
            .tunnel
            .block_owned_policy
            .store(true, Ordering::SeqCst);
        let apply = tokio::spawn({
            let fixture = fixture.clone();
            async move { fixture.core.synchronize_split_tunnel(1_100, true).await }
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            fixture.tunnel.owned_policy_entered.notified(),
        )
        .await
        .unwrap();
        let mut split = fixture.split_store.load().unwrap();
        split.applied_physical_network_fingerprint = Some("network-a".into());
        fixture.split_store.save(&split).unwrap();
        // The independent replacement may be ordinary too. Its available
        // recipe/baseline is observable through the existing legacy poller.
        observed.session_id = None;
        fixture
            .tunnel
            .independent_native_owner
            .store(false, Ordering::SeqCst);
        *fixture.tunnel.owned_session_scope.lock().unwrap() = None;
        *fixture.tunnel.status.lock().unwrap() = TunnelStatus::Running;
        let bootstrap =
            bootstrap_observation_while_recovery_pending(&fixture, observed.clone()).await;
        fixture.tunnel.owned_policy_release.notify_one();
        assert!(matches!(
            apply.await.unwrap(),
            Err(CoreError::StartCancelled)
        ));
        bootstrap.await.unwrap().unwrap();
        fixture.tunnel.set_fingerprints(["network-b"]);
        assert_eq!(
            fixture.core.poll_physical_network(1_200).await.unwrap(),
            PhysicalNetworkPollOutcome::ChangePending,
            "S2's restored available recipe and baseline must survive S1's {outcome:?} reply"
        );
        assert_eq!(fixture.core.state().await.connection, Some(observed));
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn android_policy_restart_does_not_dispatch_user_stop() {
    for fail_new_policy in [false, true] {
        let fixture = restart_metadata_fixture(EgressMode::PreferIpv6).await;
        let lease = fixture.core.state().await.connection.unwrap().lease_id;
        fixture
            .tunnel
            .preserve_restart_intent
            .store(true, Ordering::SeqCst);
        let mut changed = policy(SplitTunnelMode::ExcludeSelected);
        changed.revision = 9;
        changed.policy_hash = format!("sha256:{}", "b".repeat(64));
        changed.selected_packages = vec!["com.example.chat".into()];
        fixture.api.set_policy(changed);
        fixture.api.set_revision(9, 2);
        fixture
            .tunnel
            .fail_next_starts
            .store(usize::from(fail_new_policy), Ordering::SeqCst);
        fixture
            .core
            .synchronize_split_tunnel(1_600, false)
            .await
            .unwrap();
        assert_eq!(
            fixture.tunnel.stops.load(Ordering::SeqCst),
            0,
            "a policy replacement must not cancel the durable Android intent"
        );
        assert_eq!(fixture.core.state().await.phase, Phase::Connected);
        assert_eq!(
            fixture.core.state().await.connection.unwrap().lease_id,
            lease
        );
        assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.tunnel.restart_starts.load(Ordering::SeqCst),
            1 + usize::from(fail_new_policy)
        );
        fixture.core.stop_locally().await.unwrap();
        assert_eq!(
            fixture.tunnel.stops.load(Ordering::SeqCst),
            1,
            "explicit Stop must still close the native tunnel"
        );
    }
}

#[tokio::test]
async fn policy_rollback_preserves_dns46_connection_metadata() {
    check_policy_restart_metadata(true).await;
}

async fn check_policy_restart_metadata(fail_new_policy: bool) {
    for mode in [EgressMode::PreferIpv6, EgressMode::Ipv4] {
        let fixture = restart_metadata_fixture(mode).await;
        let connection = fixture.core.state().await.connection.unwrap();
        let mut changed = policy(SplitTunnelMode::ExcludeSelected);
        changed.revision = 9;
        changed.policy_hash = format!("sha256:{}", "b".repeat(64));
        changed.selected_packages = vec!["com.example.chat".into()];
        fixture.api.set_policy(changed);
        fixture.api.set_revision(9, 2);
        fixture
            .tunnel
            .fail_next_starts
            .store(usize::from(fail_new_policy), Ordering::SeqCst);
        assert!(matches!(
            fixture
                .core
                .synchronize_split_tunnel(1_600, false)
                .await
                .unwrap(),
            SplitTunnelSyncOutcome::Updated { reconnected: true }
        ));
        assert_eq!(fixture.core.state().await.phase, Phase::Connected);
        assert_eq!(
            fixture
                .api
                .apply_results
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .status,
            if fail_new_policy {
                SplitTunnelApplyStatus::RolledBack
            } else {
                SplitTunnelApplyStatus::Applied
            }
        );
        let starts = fixture.tunnel.start_metadata.lock().unwrap();
        assert_eq!(starts.len(), if fail_new_policy { 3 } else { 2 });
        // Check rollback first so its missing metadata has a separate RED regression.
        assert_local_restart_metadata(starts.last().unwrap(), &connection);
        assert_local_restart_metadata(&starts[1], &connection);
        assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn network_restart_and_retry_preserve_dns46_connection_metadata() {
    for failed_starts in [0, 1] {
        let fixture = restart_metadata_fixture(EgressMode::PreferIpv6).await;
        fixture
            .tunnel
            .preserve_restart_intent
            .store(true, Ordering::SeqCst);
        let connection = fixture.core.state().await.connection.unwrap();
        fixture.tunnel.set_fingerprints(["network-b", "network-b"]);
        assert_eq!(
            fixture.core.poll_physical_network(1_100).await.unwrap(),
            PhysicalNetworkPollOutcome::ChangePending
        );
        fixture
            .tunnel
            .fail_next_starts
            .store(failed_starts, Ordering::SeqCst);
        assert_eq!(
            fixture.core.poll_physical_network(1_130).await.unwrap(),
            PhysicalNetworkPollOutcome::Reconnected
        );
        let starts = fixture.tunnel.start_metadata.lock().unwrap();
        assert_eq!(starts.len(), 2 + failed_starts);
        for start in &starts[1..] {
            assert_local_restart_metadata(start, &connection);
        }
        assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.tunnel.restart_starts.load(Ordering::SeqCst),
            1 + failed_starts
        );
    }
}

async fn metadata_recovery_fixture() -> (Arc<CoordinatorFixture>, Connection) {
    let fixture = Arc::new(restart_metadata_fixture(EgressMode::PreferIpv6).await);
    let mut original = fixture.core.state().await.connection.unwrap();
    original.status = LeaseStatus::Issued;
    fixture.api.set_bootstrap_connection(original.clone());
    fixture.core.bootstrap(1_020).await.unwrap();
    fixture
        .tunnel
        .preserve_restart_intent
        .store(true, Ordering::SeqCst);
    (fixture, original)
}

async fn bootstrap_observation_while_recovery_pending(
    fixture: &Arc<CoordinatorFixture>,
    updated: Connection,
) -> tokio::task::JoinHandle<Result<Bootstrap, CoreError>> {
    fixture.api.set_bootstrap_connection(updated.clone());
    let count = fixture
        .logger
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.kind == "bootstrap.completed")
        .count();
    let bootstrap = tokio::spawn({
        let fixture = fixture.clone();
        async move { fixture.core.bootstrap(1_030).await }
    });
    // The observation is published before bootstrap's final report flush,
    // which is allowed to wait for recovery's split gate.
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while fixture
            .logger
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.kind == "bootstrap.completed")
            .count()
            == count
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.core.state().await.connection, Some(updated));
    bootstrap
}

#[tokio::test]
async fn stalled_recovery_preserves_same_execution_bootstrap_metadata() {
    let (fixture, original) = metadata_recovery_fixture().await;
    fixture.tunnel.block_restart.store(true, Ordering::SeqCst);
    let recovery = tokio::spawn({
        let fixture = fixture.clone();
        let lease_id = original.lease_id.clone();
        async move {
            fixture
                .core
                .recover_stalled_data_plane(&lease_id, StalledDataPlaneRecovery::RestartLocalTunnel)
                .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while fixture.tunnel.restart_starts.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut updated = original;
    updated.status = LeaseStatus::Connected;
    updated.probe_url = Some("https://probe.example/updated".into());
    let bootstrap = bootstrap_observation_while_recovery_pending(&fixture, updated.clone()).await;
    fixture.tunnel.block_restart.store(false, Ordering::SeqCst);
    fixture.tunnel.restart_release.notify_one();
    let result = recovery.await.unwrap();
    bootstrap.await.unwrap().unwrap();
    assert_eq!(
        result.unwrap(),
        StalledDataPlaneRecoveryOutcome::Reconnected
    );
    assert_eq!(fixture.core.state().await.connection, Some(updated));
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(
        fixture.tunnel.status().await.unwrap(),
        TunnelStatus::Running
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
    assert!(!fixture
        .core
        .split_tunnel_settings_require_reconnect(&same_split_settings())
        .await
        .unwrap());
}

#[tokio::test]
async fn network_recovery_preserves_metadata_refreshed_before_native_retirement() {
    let (fixture, original) = metadata_recovery_fixture().await;
    fixture.tunnel.set_fingerprints(["network-b", "network-b"]);
    assert_eq!(
        fixture.core.poll_physical_network(1_100).await.unwrap(),
        PhysicalNetworkPollOutcome::ChangePending
    );
    let calls = fixture.tunnel.fingerprint_calls.load(Ordering::SeqCst);
    fixture
        .tunnel
        .block_fingerprint
        .store(true, Ordering::SeqCst);
    let recovery = tokio::spawn({
        let fixture = fixture.clone();
        async move { fixture.core.poll_physical_network(1_130).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while fixture.tunnel.fingerprint_calls.load(Ordering::SeqCst) == calls {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut updated = original;
    updated.status = LeaseStatus::Connected;
    updated.probe_url = Some("https://probe.example/updated".into());
    let bootstrap = bootstrap_observation_while_recovery_pending(&fixture, updated.clone()).await;
    fixture
        .tunnel
        .block_fingerprint
        .store(false, Ordering::SeqCst);
    fixture.tunnel.fingerprint_release.notify_one();
    let result = recovery.await.unwrap();
    bootstrap.await.unwrap().unwrap();
    assert_eq!(result.unwrap(), PhysicalNetworkPollOutcome::Reconnected);
    assert_eq!(fixture.core.state().await.connection, Some(updated));
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
    assert!(!fixture
        .core
        .split_tunnel_settings_require_reconnect(&same_split_settings())
        .await
        .unwrap());
}

#[tokio::test]
async fn metadata_recovery_publication_rejects_changed_execution_or_retired_lease() {
    for change in 0..12 {
        let (fixture, original) = metadata_recovery_fixture().await;
        fixture.tunnel.block_restart.store(true, Ordering::SeqCst);
        let recovery = tokio::spawn({
            let fixture = fixture.clone();
            let lease_id = original.lease_id.clone();
            async move {
                fixture
                    .core
                    .recover_stalled_data_plane(
                        &lease_id,
                        StalledDataPlaneRecovery::RestartLocalTunnel,
                    )
                    .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while fixture.tunnel.restart_starts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut updated = original.clone();
        match change {
            0 => updated.lease_id = "22222222-2222-4222-8222-222222222222".into(),
            1 => updated.session_id = Some("33333333-3333-4333-8333-333333333333".into()),
            2 => updated.pool_id = Some("another-pool".into()),
            3 => updated.layer = Layer::Stray,
            4 => updated.transport_protocol = nelomai_contracts::TransportProtocol::Amneziawg3,
            5 => updated.tic_connection_mode = TicConnectionMode::Dynamic,
            6 => updated.route_mode = RouteMode::Standalone,
            7 => updated.egress_mode = EgressMode::Ipv4,
            8 => updated.pinned = !updated.pinned,
            9 => updated.status = LeaseStatus::Released,
            10 => updated.status = LeaseStatus::Warm,
            11 => updated.stopped_at = Some("2026-10-12T00:00:00Z".into()),
            _ => unreachable!(),
        }
        assert_ne!(
            updated, original,
            "negative case {change} must change the observed execution"
        );
        let bootstrap =
            bootstrap_observation_while_recovery_pending(&fixture, updated.clone()).await;
        fixture.tunnel.block_restart.store(false, Ordering::SeqCst);
        fixture.tunnel.restart_release.notify_one();
        let result = recovery.await.unwrap();
        bootstrap.await.unwrap().unwrap();
        assert!(
            matches!(result, Err(CoreError::StartCancelled)),
            "changed execution case {change}: {result:?}"
        );
        assert_eq!(fixture.core.state().await.connection, Some(updated));
        assert_eq!(
            fixture.tunnel.status().await.unwrap(),
            TunnelStatus::Stopped,
            "changed execution case {change} must compensate the dispatched restart"
        );
        assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn network_recovery_rejects_changed_session_and_closes_dispatched_native_start() {
    let (fixture, original) = metadata_recovery_fixture().await;
    fixture.tunnel.set_fingerprints(["network-b", "network-b"]);
    assert_eq!(
        fixture.core.poll_physical_network(1_100).await.unwrap(),
        PhysicalNetworkPollOutcome::ChangePending
    );
    fixture.tunnel.block_restart.store(true, Ordering::SeqCst);
    let recovery = tokio::spawn({
        let fixture = fixture.clone();
        async move { fixture.core.poll_physical_network(1_130).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while fixture.tunnel.restart_starts.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut updated = original;
    updated.session_id = Some("33333333-3333-4333-8333-333333333333".into());
    let bootstrap = bootstrap_observation_while_recovery_pending(&fixture, updated.clone()).await;
    fixture.tunnel.block_restart.store(false, Ordering::SeqCst);
    fixture.tunnel.restart_release.notify_one();
    assert!(matches!(
        recovery.await.unwrap(),
        Err(CoreError::StartCancelled)
    ));
    bootstrap.await.unwrap().unwrap();
    assert_eq!(fixture.core.state().await.connection, Some(updated));
    assert_eq!(
        fixture.tunnel.status().await.unwrap(),
        TunnelStatus::Stopped
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rejected_recovery_distinguishes_native_handoff_from_failed_cleanup() {
    for native_handoff in [false, true] {
        let (fixture, original) = metadata_recovery_fixture().await;
        fixture.tunnel.block_restart.store(true, Ordering::SeqCst);
        let recovery = tokio::spawn({
            let fixture = fixture.clone();
            let lease_id = original.lease_id.clone();
            async move {
                fixture
                    .core
                    .recover_stalled_data_plane(
                        &lease_id,
                        StalledDataPlaneRecovery::RestartLocalTunnel,
                    )
                    .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while fixture.tunnel.restart_starts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut updated = original;
        updated.session_id = Some("33333333-3333-4333-8333-333333333333".into());
        let bootstrap =
            bootstrap_observation_while_recovery_pending(&fixture, updated.clone()).await;
        fixture
            .tunnel
            .independent_native_owner
            .store(native_handoff, Ordering::SeqCst);
        fixture.tunnel.fail_next_stops.store(1, Ordering::SeqCst);
        fixture
            .tunnel
            .keep_running_on_stop_failure
            .store(true, Ordering::SeqCst);
        fixture.tunnel.block_restart.store(false, Ordering::SeqCst);
        fixture.tunnel.restart_release.notify_one();
        let result = recovery.await.unwrap();
        bootstrap.await.unwrap().unwrap();
        let current = fixture.core.state().await;
        assert_eq!(current.connection, Some(updated));
        assert_eq!(
            fixture.tunnel.status().await.unwrap(),
            TunnelStatus::Running
        );
        assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
        if native_handoff {
            assert!(matches!(result, Err(CoreError::StartCancelled)));
            assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
            assert_eq!(current.phase, Phase::Connected);
        } else {
            assert!(
                matches!(result, Err(CoreError::Tunnel(ref code)) if code == "test_stop_failed")
            );
            assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
            assert_eq!(current.phase, Phase::Error);
        }
    }
}

#[tokio::test]
async fn policy_replacement_retires_confirmation_before_bootstrap_and_queued_save() {
    let fixture = Arc::new(restart_metadata_fixture(EgressMode::PreferIpv6).await);
    let original = fixture.core.state().await.connection.unwrap();
    fixture
        .tunnel
        .preserve_restart_intent
        .store(true, Ordering::SeqCst);
    fixture.tunnel.block_restart.store(true, Ordering::SeqCst);
    let mut changed = policy(SplitTunnelMode::ExcludeSelected);
    changed.revision = 9;
    changed.policy_hash = format!("sha256:{}", "b".repeat(64));
    changed.selected_packages = vec!["com.example.chat".into()];
    fixture.api.set_policy(changed);
    fixture.api.set_revision(9, 2);
    let replacement = tokio::spawn({
        let fixture = fixture.clone();
        async move { fixture.core.synchronize_split_tunnel(1_600, false).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while fixture.tunnel.restart_starts.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.core.state().await.phase, Phase::Connecting);
    let bootstrap = bootstrap_observation_while_recovery_pending(&fixture, original).await;
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    let request = same_split_settings();
    let requires_confirmation = fixture
        .core
        .split_tunnel_settings_require_reconnect(&request)
        .await
        .unwrap();
    // The API fixture returns its policy instead of interpreting PUT fields;
    // arrange policy A, the response to the requested old settings.
    fixture
        .api
        .set_policy(policy(SplitTunnelMode::ExcludeSelected));
    let save = tokio::spawn({
        let fixture = fixture.clone();
        async move {
            fixture
                .core
                .save_split_tunnel_settings(&request, 1_700)
                .await
        }
    });
    tokio::task::yield_now().await;
    fixture.tunnel.block_restart.store(false, Ordering::SeqCst);
    fixture.tunnel.restart_release.notify_one();
    assert!(matches!(
        replacement.await.unwrap().unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: true }
    ));
    save.await.unwrap().unwrap();
    bootstrap.await.unwrap().unwrap();
    let plans = fixture.tunnel.options.lock().unwrap();
    assert_eq!(plans.len(), 3);
    assert!(plans[0].package_ids.is_empty());
    assert_eq!(plans[1].package_ids, vec!["com.example.chat"]);
    assert!(plans[2].package_ids.is_empty());
    assert!(
        requires_confirmation,
        "preflight must require confirmation before a queued Save replaces pending B with A"
    );
}

async fn unchanged_warm_recovery_fixture() -> (Arc<CoordinatorFixture>, Connection) {
    let (fixture, mut connection) = metadata_recovery_fixture().await;
    connection.status = LeaseStatus::Warm;
    fixture.api.set_bootstrap_connection(connection.clone());
    fixture.core.bootstrap(1_040).await.unwrap();
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(
        fixture.core.state().await.connection,
        Some(connection.clone())
    );
    assert_eq!(
        fixture.tunnel.status().await.unwrap(),
        TunnelStatus::Running
    );
    (fixture, connection)
}

#[tokio::test]
async fn unchanged_warm_metadata_keeps_stalled_native_recovery_available() {
    let (fixture, connection) = unchanged_warm_recovery_fixture().await;
    assert_eq!(
        fixture
            .core
            .recover_stalled_data_plane(
                &connection.lease_id,
                StalledDataPlaneRecovery::RestartLocalTunnel,
            )
            .await
            .unwrap(),
        StalledDataPlaneRecoveryOutcome::Reconnected
    );
    assert_eq!(fixture.core.state().await.connection, Some(connection));
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unchanged_warm_metadata_keeps_network_native_recovery_available() {
    let (fixture, connection) = unchanged_warm_recovery_fixture().await;
    fixture.tunnel.set_fingerprints(["network-b", "network-b"]);
    assert_eq!(
        fixture.core.poll_physical_network(1_100).await.unwrap(),
        PhysicalNetworkPollOutcome::ChangePending
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_130).await.unwrap(),
        PhysicalNetworkPollOutcome::Reconnected
    );
    assert_eq!(fixture.core.state().await.connection, Some(connection));
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn metadata_recovery_refresh_does_not_bypass_explicit_disconnect() {
    let (fixture, original) = metadata_recovery_fixture().await;
    fixture.tunnel.block_restart.store(true, Ordering::SeqCst);
    let recovery = tokio::spawn({
        let fixture = fixture.clone();
        let lease_id = original.lease_id.clone();
        async move {
            fixture
                .core
                .recover_stalled_data_plane(&lease_id, StalledDataPlaneRecovery::RestartLocalTunnel)
                .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while fixture.tunnel.restart_starts.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut updated = original;
    updated.status = LeaseStatus::Connected;
    let bootstrap = bootstrap_observation_while_recovery_pending(&fixture, updated).await;
    fixture.local.stop_local_on_disconnect().await.unwrap();
    fixture.tunnel.block_restart.store(false, Ordering::SeqCst);
    fixture.tunnel.restart_release.notify_one();
    let result = recovery.await.unwrap();
    assert!(matches!(
        bootstrap.await.unwrap(),
        Err(CoreError::StartCancelled)
    ));
    assert!(matches!(result, Err(CoreError::StartCancelled)));
    assert_eq!(
        fixture.tunnel.status().await.unwrap(),
        TunnelStatus::Stopped
    );
    assert_eq!(fixture.core.state().await.phase, Phase::Error);
    assert!(fixture.core.state().await.connection.is_none());
}

#[tokio::test]
async fn stalled_restart_and_retry_preserve_dns46_connection_metadata() {
    for failed_starts in [0, 1] {
        let fixture = restart_metadata_fixture(EgressMode::PreferIpv6).await;
        fixture
            .tunnel
            .preserve_restart_intent
            .store(true, Ordering::SeqCst);
        let connection = fixture.core.state().await.connection.unwrap();
        fixture
            .tunnel
            .fail_next_starts
            .store(failed_starts, Ordering::SeqCst);
        assert_eq!(
            fixture
                .core
                .recover_stalled_data_plane(
                    &connection.lease_id,
                    StalledDataPlaneRecovery::RestartLocalTunnel
                )
                .await
                .unwrap(),
            StalledDataPlaneRecoveryOutcome::Reconnected
        );
        let starts = fixture.tunnel.start_metadata.lock().unwrap();
        assert_eq!(starts.len(), 2 + failed_starts);
        for start in &starts[1..] {
            assert_local_restart_metadata(start, &connection);
        }
        assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.tunnel.restart_starts.load(Ordering::SeqCst),
            1 + failed_starts
        );
    }
}

#[tokio::test]
async fn nlm071_network_restart_completion_cannot_replace_disconnect_or_logout() {
    for logout in [false, true] {
        for fail in [false, true] {
            let fixture = Arc::new(restart_metadata_fixture(EgressMode::PreferIpv6).await);
            fixture
                .tunnel
                .preserve_restart_intent
                .store(true, Ordering::SeqCst);
            fixture.tunnel.set_fingerprints(["network-b", "network-b"]);
            assert_eq!(
                fixture.core.poll_physical_network(1_100).await.unwrap(),
                PhysicalNetworkPollOutcome::ChangePending
            );
            fixture.tunnel.block_restart.store(true, Ordering::SeqCst);
            fixture
                .tunnel
                .fail_next_starts
                .store(if fail { 2 } else { 0 }, Ordering::SeqCst);
            let recovery = tokio::spawn({
                let fixture = fixture.clone();
                async move { fixture.core.poll_physical_network(1_130).await }
            });
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while fixture.tunnel.restart_starts.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if logout {
                fixture.local.stop_local().await.unwrap();
            } else {
                fixture.local.stop_local_on_disconnect().await.unwrap();
            }
            let expected = if logout {
                Phase::SignedOut
            } else {
                Phase::Error
            };
            let stored_after_stop = fixture.secret_store.load().unwrap();
            fixture.tunnel.block_restart.store(false, Ordering::SeqCst);
            fixture.tunnel.restart_release.notify_one();
            let result = recovery.await.unwrap();
            assert_eq!(fixture.core.state().await.phase, expected);
            assert!(fixture.core.state().await.connection.is_none());
            assert_eq!(
                fixture.tunnel.status().await.unwrap(),
                TunnelStatus::Stopped
            );
            assert_eq!(fixture.tunnel.restart_starts.load(Ordering::SeqCst), 1);
            assert!(
                matches!(result, Err(CoreError::StartCancelled)),
                "{result:?}"
            );
            assert_eq!(fixture.secret_store.load().unwrap(), stored_after_stop);
        }
    }
}

#[tokio::test]
async fn nlm071_network_detection_after_disconnect_never_dispatches_restart() {
    let fixture = Arc::new(restart_metadata_fixture(EgressMode::PreferIpv6).await);
    fixture
        .tunnel
        .preserve_restart_intent
        .store(true, Ordering::SeqCst);
    fixture.tunnel.set_fingerprints(["network-b", "network-b"]);
    fixture.core.poll_physical_network(1_100).await.unwrap();
    let previous_probes = fixture.tunnel.fingerprint_calls.load(Ordering::SeqCst);
    fixture
        .tunnel
        .block_fingerprint
        .store(true, Ordering::SeqCst);
    let recovery = tokio::spawn({
        let fixture = fixture.clone();
        async move { fixture.core.poll_physical_network(1_130).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while fixture.tunnel.fingerprint_calls.load(Ordering::SeqCst) == previous_probes {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.local.stop_local_on_disconnect().await.unwrap();
    fixture
        .tunnel
        .block_fingerprint
        .store(false, Ordering::SeqCst);
    fixture.tunnel.fingerprint_release.notify_one();
    assert!(matches!(
        recovery.await.unwrap(),
        Err(CoreError::StartCancelled)
    ));
    assert_eq!(fixture.tunnel.restart_starts.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.core.state().await.phase, Phase::Error);
    assert!(fixture.core.state().await.connection.is_none());
    assert_eq!(
        fixture.tunnel.status().await.unwrap(),
        TunnelStatus::Stopped
    );
}

async fn restart_metadata_fixture(mode: EgressMode) -> CoordinatorFixture {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture.tunnel.set_fingerprints(["network-a"]);
    let mut options = ConnectOptions::android_default();
    options.egress_mode = mode;
    fixture.core.start(options, 1_010).await.unwrap();
    assert_eq!(
        fixture.core.state().await.connection.unwrap().egress_mode,
        mode
    );
    // Establish that the normal Start already carries this server-accepted mode.
    assert_eq!(
        fixture.tunnel.start_metadata.lock().unwrap()[0]
            .0
            .as_ref()
            .unwrap()
            .egress_mode,
        mode
    );
    fixture
}

fn assert_local_restart_metadata(
    start: &(Option<QuickConnection>, QuickReconnect),
    connection: &Connection,
) {
    let metadata = start
        .0
        .as_ref()
        .expect("local restart must retain the current connection's DNS mode");
    assert_eq!(metadata.lease_id, connection.lease_id);
    assert_eq!(metadata.layer, connection.layer);
    assert_eq!(metadata.tic_connection_mode, connection.tic_connection_mode);
    assert_eq!(metadata.route_mode, connection.route_mode);
    assert_eq!(metadata.egress_mode, connection.egress_mode);
    assert!(
        !metadata.allow_alternate,
        "local restart must not select another lease"
    );
    assert_eq!(
        start.1,
        QuickReconnect::Disabled,
        "metadata must not enable quick caching"
    );
}

#[tokio::test]
async fn unchanged_hash_does_not_reconnect_but_changed_policy_rolls_back_atomically() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture
        .core
        .start(ConnectOptions::android_default(), 1_010)
        .await
        .unwrap();
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);

    let mut same_hash = policy(SplitTunnelMode::ExcludeSelected);
    same_hash.revision = 8;
    fixture.api.set_policy(same_hash);
    fixture.api.set_revision(8, 2);
    assert!(matches!(
        fixture
            .core
            .synchronize_split_tunnel(1_300, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: false }
    ));
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);

    let mut changed = policy(SplitTunnelMode::ExcludeSelected);
    changed.revision = 9;
    changed.policy_hash = format!("sha256:{}", "b".repeat(64));
    changed.selected_packages = vec!["com.example.chat".to_string()];
    fixture.api.set_policy(changed);
    fixture.api.set_revision(9, 2);
    fixture.tunnel.fail_next_starts.store(1, Ordering::SeqCst);

    assert!(matches!(
        fixture
            .core
            .synchronize_split_tunnel(1_600, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: true }
    ));
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::RolledBack
    );
    let failed_state = fixture.split_store.load().unwrap();
    assert_eq!(
        failed_state.failed_policy_hash.as_deref(),
        Some(format!("sha256:{}", "b".repeat(64)).as_str())
    );
    assert_eq!(failed_state.failed_policy_retry_after_unix, Some(5_200));
    assert_eq!(
        fixture
            .core
            .cached_split_tunnel_policy()
            .unwrap()
            .unwrap()
            .policy_hash,
        format!("sha256:{}", "a".repeat(64))
    );

    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_900, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Unchanged
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 3);

    assert!(matches!(
        fixture
            .core
            .synchronize_split_tunnel(5_200, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: true }
    ));
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 4);
    assert!(fixture
        .split_store
        .load()
        .unwrap()
        .failed_policy_hash
        .is_none());
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::Applied
    );
}

#[tokio::test]
async fn forced_sync_reapplies_an_unchanged_policy_when_android_inventory_changes() {
    let fixture = coordinator_fixture(android_35_capabilities());
    let mut current_policy = policy(SplitTunnelMode::ExcludeSelected);
    current_policy.mandatory_excluded_packages = vec!["com.example.new".to_string()];
    fixture.api.set_policy(current_policy);
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture
        .core
        .start(ConnectOptions::android_default(), 1_010)
        .await
        .unwrap();
    assert!(fixture
        .tunnel
        .options
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .package_ids
        .is_empty());

    let mut updated_inventory = installed();
    updated_inventory.push(SplitTunnelSelectedPackage {
        package_id: "com.example.new".to_string(),
        display_name: "New".to_string(),
    });
    fixture
        .core
        .set_split_tunnel_installed_packages(updated_inventory);

    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_300, true)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: true }
    );
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .tunnel
            .options
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .package_ids,
        ["com.example.new"]
    );
}

#[tokio::test]
async fn failed_policy_stop_is_reported_and_respects_retry_cooldown() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture
        .core
        .start(ConnectOptions::android_default(), 1_010)
        .await
        .unwrap();

    let mut changed = policy(SplitTunnelMode::ExcludeSelected);
    changed.revision = 8;
    changed.policy_hash = format!("sha256:{}", "b".repeat(64));
    changed.selected_packages = vec!["com.example.chat".to_string()];
    fixture.api.set_policy(changed);
    fixture.api.set_revision(8, 2);
    fixture.tunnel.fail_next_stops.store(1, Ordering::SeqCst);
    fixture
        .tunnel
        .keep_running_on_stop_failure
        .store(true, Ordering::SeqCst);

    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_300, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: false }
    );
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
    let failed_state = fixture.split_store.load().unwrap();
    assert_eq!(
        failed_state.failed_policy_hash.as_deref(),
        Some(format!("sha256:{}", "b".repeat(64)).as_str())
    );
    assert_eq!(failed_state.failed_policy_retry_after_unix, Some(4_900));
    let failed_result = fixture.api.apply_results.lock().unwrap().last().cloned();
    assert_eq!(
        failed_result.as_ref().map(|result| result.status),
        Some(SplitTunnelApplyStatus::Failed)
    );
    assert_eq!(
        failed_result.and_then(|result| result.error_code),
        Some("split_tunnel_stop_failed".to_string())
    );

    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_600, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Unchanged
    );
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);

    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(4_900, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: true }
    );
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 2);
    assert!(fixture
        .split_store
        .load()
        .unwrap()
        .failed_policy_hash
        .is_none());
}

#[tokio::test]
async fn changed_hash_with_identical_effective_routes_is_applied_without_reconnect() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture
        .core
        .start(ConnectOptions::android_default(), 1_010)
        .await
        .unwrap();

    let mut changed = policy(SplitTunnelMode::ExcludeSelected);
    changed.revision = 8;
    changed.policy_hash = format!("sha256:{}", "b".repeat(64));
    fixture.api.set_policy(changed.clone());
    fixture.api.set_revision(8, 3);

    assert!(matches!(
        fixture
            .core
            .synchronize_split_tunnel(1_300, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: false }
    ));
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .split_store
            .load()
            .unwrap()
            .working_policy_hash
            .as_deref(),
        Some(changed.policy_hash.as_str())
    );
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::Applied
    );
}

#[tokio::test]
async fn failed_reapply_and_failed_rollback_leave_the_tunnel_stopped() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture
        .core
        .start(ConnectOptions::android_default(), 1_010)
        .await
        .unwrap();

    let mut changed = policy(SplitTunnelMode::ExcludeSelected);
    changed.revision = 8;
    changed.policy_hash = format!("sha256:{}", "c".repeat(64));
    changed.selected_packages = vec!["com.example.chat".to_string()];
    fixture.api.set_policy(changed);
    fixture.api.set_revision(8, 2);
    fixture.tunnel.fail_next_starts.store(2, Ordering::SeqCst);

    fixture
        .core
        .synchronize_split_tunnel(1_300, false)
        .await
        .unwrap();
    assert_eq!(fixture.core.state().await.phase, Phase::Stopping);
    assert_eq!(
        *fixture.tunnel.status.lock().unwrap(),
        TunnelStatus::Stopped
    );
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::Failed
    );
}

#[tokio::test]
async fn settings_save_reports_apply_and_rollback_failures() {
    for (failed_starts, expected_code, expected_phase) in [
        (1, "split_tunnel_apply_failed", Phase::Connected),
        (2, "split_tunnel_rollback_failed", Phase::Stopping),
    ] {
        let fixture = coordinator_fixture(android_35_capabilities());
        fixture
            .core
            .synchronize_split_tunnel(1_000, false)
            .await
            .unwrap();
        fixture
            .core
            .start(ConnectOptions::android_default(), 1_010)
            .await
            .unwrap();

        let mut changed = policy(SplitTunnelMode::ExcludeSelected);
        changed.revision = 8;
        changed.policy_hash = format!("sha256:{}", "f".repeat(64));
        changed.selected_packages = vec!["com.example.chat".to_string()];
        fixture.api.set_policy(changed);
        fixture
            .tunnel
            .fail_next_starts
            .store(failed_starts, Ordering::SeqCst);

        let error = fixture
            .core
            .save_split_tunnel_settings(
                &SplitTunnelSettingsUpdate {
                    mode: SplitTunnelMode::ExcludeSelected,
                    exclude_local_networks: true,
                    selected_packages: vec![SplitTunnelSelectedPackage {
                        package_id: "com.example.chat".to_string(),
                        display_name: "Chat".to_string(),
                    }],
                },
                1_100,
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            CoreError::SplitTunnel(ref code) if code == expected_code
        ));
        assert_eq!(fixture.core.state().await.phase, expected_phase);
        assert_eq!(
            fixture.core.split_tunnel_warning().await.as_deref(),
            Some(expected_code)
        );
    }
}

#[tokio::test]
async fn logout_fences_failed_policy_stop_without_restoring_connection() {
    let fixture = Arc::new(coordinator_fixture(android_35_capabilities()));
    fixture
        .core
        .synchronize_split_tunnel(1000, false)
        .await
        .unwrap();
    fixture
        .core
        .start(ConnectOptions::android_default(), 1010)
        .await
        .unwrap();
    let mut changed = policy(SplitTunnelMode::ExcludeSelected);
    changed.revision = 8;
    changed.policy_hash = format!("sha256:{}", "f".repeat(64));
    changed.selected_packages = vec!["com.example.chat".into()];
    fixture.api.set_policy(changed);
    fixture.tunnel.block_stop.store(true, Ordering::SeqCst);
    let worker = fixture.clone();
    let pending = tokio::spawn(async move {
        worker
            .core
            .save_split_tunnel_settings(
                &SplitTunnelSettingsUpdate {
                    mode: SplitTunnelMode::ExcludeSelected,
                    exclude_local_networks: true,
                    selected_packages: vec![SplitTunnelSelectedPackage {
                        package_id: "com.example.chat".into(),
                        display_name: "Chat".into(),
                    }],
                },
                1100,
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while fixture.tunnel.stops.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let gates = fixture.core.runtime_writer_gates();
    let mut admission = Box::pin(gates.quiesce());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut admission)
            .await
            .is_err(),
        "admission must drain the real held split writer"
    );
    fixture.tunnel.block_stop.store(false, Ordering::SeqCst);
    tokio::time::timeout(std::time::Duration::from_secs(2), fixture.core.sign_out())
        .await
        .expect("logout does not wait for admission")
        .unwrap();
    let cleanup = fixture.secret_store.load().unwrap().unwrap();
    fixture.tunnel.fail_next_stops.store(1, Ordering::SeqCst);
    fixture.tunnel.stop_release.notify_one();
    assert!(matches!(
        pending.await.unwrap(),
        Err(CoreError::StartCancelled)
    ));
    let _quiescence = tokio::time::timeout(std::time::Duration::from_secs(2), admission)
        .await
        .unwrap();
    assert_eq!(fixture.core.state().await.phase, Phase::SignedOut);
    assert!(fixture.core.state().await.connection.is_none());
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.secret_store.load().unwrap().unwrap(), cleanup);
}

#[tokio::test]
async fn started_tunnel_remains_connected_when_split_state_persistence_fails() {
    let api = Arc::new(CoordinatorApi::new());
    let secret_store = Arc::new(TestSecretStore::new(StoredAuth {
        install_secret: "install".to_string(),
        access_token: Some("access".to_string()),
        refresh_token: Some("refresh".to_string()),
        saved_connection: None,
        pinned_connection: None,
        pending_start: None,
        pending_stalled_stop: None,
        pending_compensation_stop: None,
        compatibility: None,
    }));
    let tunnel = Arc::new(CoordinatorTunnel {
        capabilities: android_35_capabilities(),
        ..CoordinatorTunnel::default()
    });
    let split_store = Arc::new(FailingSplitTunnelStore::default());
    let logger = Arc::new(TestLogger::default());
    let core = support::core_with_split(
        api,
        secret_store,
        split_store.clone(),
        tunnel.clone(),
        logger.clone(),
    );
    core.set_split_tunnel_installed_packages(installed());
    core.synchronize_split_tunnel(1_000, false).await.unwrap();
    split_store.fail_saves.store(true, Ordering::SeqCst);

    core.start(ConnectOptions::android_default(), 1_010)
        .await
        .expect("a bookkeeping failure must not turn a running tunnel into a failed start");

    assert_eq!(core.state().await.phase, Phase::Connected);
    assert_eq!(*tunnel.status.lock().unwrap(), TunnelStatus::Running);
    assert_eq!(
        core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_state_save_failed")
    );
    assert!(logger
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|event| event.kind == "split_tunnel.state_record_failed"));
}

#[tokio::test]
async fn android_32_syncs_split_policy_without_reconnect() {
    let fixture = coordinator_fixture(TunnelCapabilities {
        platform: TunnelPlatform::Android,
        android_api_level: Some(32),
        address_split_tunnel: false,
        application_split_tunnel: false,
    });
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture
        .core
        .start(ConnectOptions::android_default(), 1_010)
        .await
        .unwrap();
    let starts = fixture.tunnel.starts.load(Ordering::SeqCst);

    let mut changed = policy(SplitTunnelMode::ExcludeSelected);
    changed.revision = 8;
    changed.policy_hash = format!("sha256:{}", "d".repeat(64));
    fixture.api.set_policy(changed);
    fixture.api.set_revision(8, 2);
    fixture
        .core
        .synchronize_split_tunnel(1_300, false)
        .await
        .unwrap();

    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), starts);
    assert_eq!(
        fixture.tunnel.options.lock().unwrap().last().unwrap(),
        &TunnelOptions::default()
    );
}

#[tokio::test]
async fn settings_confirmation_depends_on_the_effective_connected_policy() {
    let changed_request = SplitTunnelSettingsUpdate {
        mode: SplitTunnelMode::ExcludeSelected,
        exclude_local_networks: true,
        selected_packages: vec![SplitTunnelSelectedPackage {
            package_id: "com.example.chat".to_string(),
            display_name: "Chat".to_string(),
        }],
    };

    let active = coordinator_fixture(android_35_capabilities());
    active.core.set_split_tunnel_installed_packages(installed());
    active
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    active
        .core
        .start(ConnectOptions::android_default(), 1_010)
        .await
        .unwrap();
    assert!(active
        .core
        .split_tunnel_settings_require_reconnect(&changed_request)
        .await
        .unwrap());

    let standalone = coordinator_fixture(android_35_capabilities());
    standalone
        .core
        .set_split_tunnel_installed_packages(installed());
    standalone
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    standalone
        .core
        .start(
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::Standalone,
                egress_mode: EgressMode::Ipv4,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_010,
        )
        .await
        .unwrap();
    assert!(standalone
        .core
        .split_tunnel_settings_require_reconnect(&changed_request)
        .await
        .unwrap());
}

#[tokio::test]
async fn settings_save_updates_cache_and_unknown_format_keeps_the_working_policy() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();

    let mut updated = policy(SplitTunnelMode::ExcludeSelected);
    updated.revision = 8;
    updated.policy_hash = format!("sha256:{}", "e".repeat(64));
    fixture.api.set_policy(updated.clone());
    fixture
        .core
        .save_split_tunnel_settings(
            &SplitTunnelSettingsUpdate {
                mode: SplitTunnelMode::ExcludeSelected,
                exclude_local_networks: true,
                selected_packages: vec![SplitTunnelSelectedPackage {
                    package_id: "com.example.chat".to_string(),
                    display_name: "Chat".to_string(),
                }],
            },
            1_100,
        )
        .await
        .unwrap();
    assert_eq!(fixture.api.settings_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .split_store
            .load()
            .unwrap()
            .cached_policy
            .unwrap()
            .policy_hash,
        updated.policy_hash
    );

    let mut unsupported = updated;
    unsupported.format_version = 3;
    unsupported.revision = 9;
    fixture.api.set_policy(unsupported);
    fixture.api.set_revision(9, 3);
    assert!(matches!(
        fixture
            .core
            .synchronize_split_tunnel(1_400, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::UnsupportedPolicy
    ));
    assert_eq!(
        fixture
            .split_store
            .load()
            .unwrap()
            .cached_policy
            .unwrap()
            .revision,
        8
    );

    let mut invalid = fixture.api.policy.lock().unwrap().clone();
    invalid.format_version = 1;
    invalid.revision = 10;
    invalid.excluded_ipv4_cidrs = vec!["203.0.113.7/24".to_string()];
    fixture.api.set_policy(invalid);
    fixture.api.set_revision(10, 4);
    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_700, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::UnsupportedPolicy
    );
    assert_eq!(
        fixture
            .split_store
            .load()
            .unwrap()
            .cached_policy
            .unwrap()
            .revision,
        8
    );
}

#[tokio::test]
async fn queued_apply_result_is_retried_without_blocking_tunnel_start() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture.api.apply_failures.store(1, Ordering::SeqCst);
    fixture
        .core
        .start(ConnectOptions::android_default(), 1_010)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .split_store
            .load()
            .unwrap()
            .pending_apply_results
            .len(),
        1
    );

    fixture
        .core
        .synchronize_split_tunnel(1_300, false)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .split_store
            .load()
            .unwrap()
            .pending_apply_results
            .len(),
        1
    );
    fixture
        .core
        .synchronize_split_tunnel(1_600, false)
        .await
        .unwrap();
    assert!(fixture
        .split_store
        .load()
        .unwrap()
        .pending_apply_results
        .is_empty());
    assert_eq!(fixture.api.apply_results.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn empty_include_selection_is_rejected_before_requesting_a_connection() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .api
        .set_policy(policy(SplitTunnelMode::IncludeSelected));
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();

    let error = fixture
        .core
        .start(ConnectOptions::android_default(), 1_010)
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "не удалось применить политику split-tunnel: split_tunnel_empty_include_selection"
    );
    assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_during_start_preflight_leaves_no_unknown_operation_to_replay() {
    let fixture = Arc::new(coordinator_fixture(capabilities(
        TunnelPlatform::Linux,
        None,
        true,
        false,
    )));
    fixture
        .api
        .set_policy(policy(SplitTunnelMode::ExcludeSelected));
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture.api.stop_succeeds.store(true, Ordering::SeqCst);
    let capability_calls = fixture.tunnel.capability_calls.load(Ordering::SeqCst);
    fixture
        .tunnel
        .block_capabilities
        .store(true, Ordering::SeqCst);
    let attempt = {
        let fixture = fixture.clone();
        tokio::spawn(async move {
            fixture
                .core
                .start(
                    ConnectOptions {
                        layer: Layer::Tic,
                        tic_connection_mode: TicConnectionMode::Personal,
                        route_mode: RouteMode::ViaTak,
                        egress_mode: EgressMode::Ipv4,
                        probes: Vec::new(),
                        allow_alternate: true,
                    },
                    1_010,
                )
                .await
        })
    };
    while fixture.tunnel.capability_calls.load(Ordering::SeqCst) == capability_calls {
        tokio::task::yield_now().await;
    }

    assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 0);
    assert!(fixture
        .secret_store
        .load()
        .unwrap()
        .unwrap()
        .pending_start
        .is_none());
    assert!(fixture.core.signal_start_cancellation());
    fixture
        .tunnel
        .block_capabilities
        .store(false, Ordering::SeqCst);
    fixture.tunnel.capabilities_release.notify_one();
    assert!(matches!(
        attempt.await.unwrap(),
        Err(CoreError::StartCancelled)
    ));

    assert!(matches!(
        fixture.core.stop().await,
        Err(CoreError::SavedConnectionUnavailable)
    ));
    let stored = fixture.secret_store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
    assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 0);
    assert_eq!(
        *fixture.tunnel.status.lock().unwrap(),
        TunnelStatus::Stopped
    );

    fixture
        .core
        .start(
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::ViaTak,
                egress_mode: EgressMode::Ipv4,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_011,
        )
        .await
        .unwrap();

    assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_while_physical_network_detection_is_in_flight_never_publishes_connected() {
    let fixture = Arc::new(coordinator_fixture(capabilities(
        TunnelPlatform::Linux,
        None,
        true,
        false,
    )));
    fixture
        .api
        .set_policy(policy(SplitTunnelMode::ExcludeSelected));
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture.tunnel.set_fingerprints(["network-a"]);
    fixture
        .tunnel
        .block_fingerprint
        .store(true, Ordering::SeqCst);
    let cancel_epoch = fixture.core.begin_start_attempt();
    let attempt = {
        let fixture = fixture.clone();
        tokio::spawn(async move {
            fixture
                .core
                .start_with_cancellation_epoch(
                    ConnectOptions {
                        layer: Layer::Tic,
                        tic_connection_mode: TicConnectionMode::Personal,
                        route_mode: RouteMode::ViaTak,
                        egress_mode: EgressMode::Ipv4,
                        probes: Vec::new(),
                        allow_alternate: true,
                    },
                    1_010,
                    cancel_epoch,
                )
                .await
        })
    };
    while fixture.tunnel.fingerprint_calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    assert!(fixture.core.signal_start_cancellation());
    fixture
        .tunnel
        .block_fingerprint
        .store(false, Ordering::SeqCst);
    fixture.tunnel.fingerprint_release.notify_one();
    let error = attempt.await.unwrap().unwrap_err();
    fixture.core.finish_start_attempt();

    assert!(matches!(error, CoreError::StartCancelled));
    assert_ne!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(
        *fixture.tunnel.status.lock().unwrap(),
        TunnelStatus::Stopped
    );
    assert!(fixture
        .secret_store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn detector_cancellation_journals_compensation_before_local_stop_and_reconstructs_in_order() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let fixture = Arc::new(coordinator_fixture(capabilities(
        TunnelPlatform::Linux,
        None,
        true,
        false,
    )));
    fixture
        .api
        .set_policy(policy(SplitTunnelMode::ExcludeSelected));
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture.api.stop_succeeds.store(true, Ordering::SeqCst);
    *fixture.api.operation_events.lock().unwrap() = Some(events.clone());
    fixture.tunnel.set_fingerprints(["network-a"]);
    fixture
        .tunnel
        .block_fingerprint
        .store(true, Ordering::SeqCst);
    fixture.tunnel.block_stop.store(true, Ordering::SeqCst);
    *fixture.tunnel.operation_events.lock().unwrap() = Some(events.clone());
    let cancel_epoch = fixture.core.begin_start_attempt();
    let attempt = {
        let fixture = fixture.clone();
        tokio::spawn(async move {
            fixture
                .core
                .start_with_cancellation_epoch(
                    ConnectOptions {
                        layer: Layer::Tic,
                        tic_connection_mode: TicConnectionMode::Personal,
                        route_mode: RouteMode::ViaTak,
                        egress_mode: EgressMode::Ipv4,
                        probes: Vec::new(),
                        allow_alternate: true,
                    },
                    1_010,
                    cancel_epoch,
                )
                .await
        })
    };
    while fixture.tunnel.fingerprint_calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    assert!(fixture.core.signal_start_cancellation());
    fixture
        .tunnel
        .block_fingerprint
        .store(false, Ordering::SeqCst);
    fixture.tunnel.fingerprint_release.notify_one();
    while fixture.tunnel.stops.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    let pending = fixture
        .secret_store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("compensation identity must be durable before local cleanup");
    assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
    assert_eq!(events.lock().unwrap().as_slice(), &["local_stop"]);

    attempt.abort();
    let _ = attempt.await;
    fixture.core.finish_start_attempt();
    fixture.tunnel.block_stop.store(false, Ordering::SeqCst);
    fixture.tunnel.stop_release.notify_waiters();
    let reconstructed = support::core_with_split(
        fixture.api.clone(),
        fixture.secret_store.clone(),
        fixture.split_store.clone(),
        fixture.tunnel.clone(),
        fixture.logger.clone(),
    );

    reconstructed
        .reconcile_pending_operation_for_retry()
        .await
        .unwrap();

    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["local_stop", "local_stop", "panel_stop"]
    );
    assert_eq!(
        fixture.api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id]
    );
    let stored = fixture.secret_store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
    assert_eq!(
        *fixture.tunnel.status.lock().unwrap(),
        TunnelStatus::Stopped
    );
}

#[tokio::test(flavor = "current_thread")]
async fn detector_cancellation_storage_failure_has_no_cleanup_side_effect_before_retry() {
    let fixture = Arc::new(coordinator_fixture(capabilities(
        TunnelPlatform::Linux,
        None,
        true,
        false,
    )));
    fixture
        .api
        .set_policy(policy(SplitTunnelMode::ExcludeSelected));
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture.api.stop_succeeds.store(true, Ordering::SeqCst);
    fixture.tunnel.set_fingerprints(["network-a"]);
    fixture
        .tunnel
        .block_fingerprint
        .store(true, Ordering::SeqCst);
    let cancel_epoch = fixture.core.begin_start_attempt();
    let attempt = {
        let fixture = fixture.clone();
        tokio::spawn(async move {
            fixture
                .core
                .start_with_cancellation_epoch(
                    ConnectOptions {
                        layer: Layer::Tic,
                        tic_connection_mode: TicConnectionMode::Personal,
                        route_mode: RouteMode::ViaTak,
                        egress_mode: EgressMode::Ipv4,
                        probes: Vec::new(),
                        allow_alternate: true,
                    },
                    1_010,
                    cancel_epoch,
                )
                .await
        })
    };
    while fixture.tunnel.fingerprint_calls.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }

    fixture
        .secret_store
        .reject_compensation_journal_once
        .store(true, Ordering::SeqCst);
    assert!(fixture.core.signal_start_cancellation());
    fixture
        .tunnel
        .block_fingerprint
        .store(false, Ordering::SeqCst);
    fixture.tunnel.fingerprint_release.notify_one();
    assert!(matches!(attempt.await.unwrap(), Err(CoreError::Storage)));
    fixture.core.finish_start_attempt();

    let stored = fixture.secret_store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_some());
    assert!(stored.pending_compensation_stop.is_none());
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        *fixture.tunnel.status.lock().unwrap(),
        TunnelStatus::Running
    );

    fixture.tunnel.block_stop.store(true, Ordering::SeqCst);
    let retry = {
        let fixture = fixture.clone();
        tokio::spawn(async move { fixture.core.stop().await })
    };
    while fixture.tunnel.stops.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let pending = fixture
        .secret_store
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .expect("retry must durably transition before local cleanup");
    assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
    fixture.tunnel.block_stop.store(false, Ordering::SeqCst);
    fixture.tunnel.stop_release.notify_one();
    retry.await.unwrap().unwrap();

    assert_eq!(
        fixture.api.stop_operation_ids.lock().unwrap().as_slice(),
        &[pending.operation_id]
    );
    let stored = fixture.secret_store.load().unwrap().unwrap();
    assert!(stored.pending_start.is_none());
    assert!(stored.pending_compensation_stop.is_none());
    assert_eq!(
        *fixture.tunnel.status.lock().unwrap(),
        TunnelStatus::Stopped
    );
}

#[tokio::test]
async fn confirmed_desktop_network_change_restarts_only_the_local_tunnel() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Linux, None, true, false));
    fixture
        .api
        .set_policy(policy(SplitTunnelMode::ExcludeSelected));
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture
        .tunnel
        .set_fingerprints(["network-a", "network-b", "network-b", "network-b"]);
    fixture
        .core
        .start(
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::ViaTak,
                egress_mode: EgressMode::Ipv4,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_010,
        )
        .await
        .unwrap();
    assert_eq!(
        fixture
            .split_store
            .load()
            .unwrap()
            .applied_physical_network_fingerprint
            .as_deref(),
        Some("network-a")
    );

    fixture
        .tunnel
        .fail_next_fingerprint
        .store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .core
            .poll_physical_network_guarded(1_099, || false)
            .await
            .unwrap(),
        PhysicalNetworkPollOutcome::RetryDeferred
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_100).await.unwrap(),
        PhysicalNetworkPollOutcome::ChangePending
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .core
            .poll_physical_network_guarded(1_129, || false)
            .await
            .unwrap(),
        PhysicalNetworkPollOutcome::RetryDeferred
    );
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.core.poll_physical_network(1_130).await.unwrap(),
        PhysicalNetworkPollOutcome::Reconnected
    );

    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(
        fixture
            .split_store
            .load()
            .unwrap()
            .applied_physical_network_fingerprint
            .as_deref(),
        Some("network-b")
    );
}

#[tokio::test]
async fn failed_network_restart_does_not_report_a_stopped_tunnel_as_connected() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Linux, None, true, false));
    fixture
        .api
        .set_policy(policy(SplitTunnelMode::ExcludeSelected));
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture
        .core
        .start(
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::ViaTak,
                egress_mode: EgressMode::Ipv4,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_010,
        )
        .await
        .unwrap();
    fixture
        .tunnel
        .set_fingerprints(["network-a", "network-b", "network-b"]);
    fixture.tunnel.fail_next_stops.store(1, Ordering::SeqCst);

    assert_eq!(
        fixture.core.poll_physical_network(1_100).await.unwrap(),
        PhysicalNetworkPollOutcome::BaselineRecorded
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_130).await.unwrap(),
        PhysicalNetworkPollOutcome::ChangePending
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_160).await.unwrap(),
        PhysicalNetworkPollOutcome::ReconnectFailed
    );

    assert_eq!(fixture.core.state().await.phase, Phase::Stopping);
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_network_reconnect_failed")
    );
}

#[tokio::test]
async fn running_tunnel_stop_failures_use_network_reconnect_backoff() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Linux, None, true, false));
    fixture
        .api
        .set_policy(policy(SplitTunnelMode::ExcludeSelected));
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture
        .core
        .start(
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::ViaTak,
                egress_mode: EgressMode::Ipv4,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_010,
        )
        .await
        .unwrap();
    fixture
        .tunnel
        .set_fingerprints(["network-a", "network-b", "network-b"]);
    fixture.tunnel.fail_next_stops.store(2, Ordering::SeqCst);
    fixture
        .tunnel
        .keep_running_on_stop_failure
        .store(true, Ordering::SeqCst);

    assert_eq!(
        fixture.core.poll_physical_network(1_100).await.unwrap(),
        PhysicalNetworkPollOutcome::BaselineRecorded
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_130).await.unwrap(),
        PhysicalNetworkPollOutcome::ChangePending
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_160).await.unwrap(),
        PhysicalNetworkPollOutcome::ReconnectFailed
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_190).await.unwrap(),
        PhysicalNetworkPollOutcome::RetryDeferred
    );
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_network_reconnect_failed")
    );
    fixture
        .core
        .synchronize_split_tunnel(1_300, false)
        .await
        .unwrap();
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_network_reconnect_failed")
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_460).await.unwrap(),
        PhysicalNetworkPollOutcome::ReconnectFailed
    );
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(
        fixture
            .logger
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.kind == "split_tunnel.network_reconnect_failed")
            .count(),
        1
    );
}

#[tokio::test]
async fn missing_saved_configuration_warns_and_uses_network_retry_backoff() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Linux, None, true, false));
    fixture
        .api
        .set_policy(policy(SplitTunnelMode::ExcludeSelected));
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture
        .core
        .start(
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::ViaTak,
                egress_mode: EgressMode::Ipv4,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_010,
        )
        .await
        .unwrap();
    let mut stored = fixture.secret_store.load().unwrap().unwrap();
    stored.saved_connection = None;
    stored.pinned_connection = None;
    fixture.secret_store.save(&stored).unwrap();
    fixture
        .tunnel
        .set_fingerprints(["network-a", "network-b", "network-b", "network-b"]);

    assert_eq!(
        fixture.core.poll_physical_network(1_100).await.unwrap(),
        PhysicalNetworkPollOutcome::BaselineRecorded
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_130).await.unwrap(),
        PhysicalNetworkPollOutcome::ChangePending
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_160).await.unwrap(),
        PhysicalNetworkPollOutcome::ReconnectFailed
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_190).await.unwrap(),
        PhysicalNetworkPollOutcome::RetryDeferred
    );
    assert_eq!(
        fixture.core.poll_physical_network(1_460).await.unwrap(),
        PhysicalNetworkPollOutcome::ReconnectFailed
    );
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_network_reconnect_failed")
    );
    assert_eq!(
        fixture
            .logger
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.kind == "split_tunnel.network_reconnect_failed")
            .count(),
        1
    );
}

#[tokio::test]
async fn missing_saved_configuration_marks_policy_failure_and_reports_it() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Linux, None, true, false));
    fixture
        .core
        .synchronize_split_tunnel(1_000, false)
        .await
        .unwrap();
    fixture
        .core
        .start(
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::ViaTak,
                egress_mode: EgressMode::Ipv4,
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_010,
        )
        .await
        .unwrap();
    let mut stored = fixture.secret_store.load().unwrap().unwrap();
    stored.saved_connection = None;
    stored.pinned_connection = None;
    fixture.secret_store.save(&stored).unwrap();
    let mut changed = policy(SplitTunnelMode::ExcludeSelected);
    changed.revision = 8;
    changed.policy_hash = format!("sha256:{}", "b".repeat(64));
    // Configuration is required only for a real native route replacement.
    changed.excluded_ipv4_cidrs = vec!["198.51.100.0/24".into()];
    fixture.api.set_policy(changed.clone());
    fixture.api.set_revision(8, 2);

    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_300, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: false }
    );

    let state = fixture.split_store.load().unwrap();
    assert_eq!(
        state.failed_policy_hash.as_deref(),
        Some(changed.policy_hash.as_str())
    );
    assert_eq!(state.failed_policy_retry_after_unix, Some(4_900));
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_saved_connection_unavailable")
    );
    let result = fixture
        .api
        .apply_results
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    assert_eq!(result.status, SplitTunnelApplyStatus::Failed);
    assert_eq!(
        result.error_code.as_deref(),
        Some("split_tunnel_saved_connection_unavailable")
    );
    assert!(fixture.logger.events.lock().unwrap().iter().any(|event| {
        event.kind == "split_tunnel.apply_failed"
            && event.code.as_deref() == Some("split_tunnel_saved_connection_unavailable")
    }));
}

#[tokio::test]
async fn background_start_with_stale_working_policy_applies_first_settings_save() {
    for cached_on in [true, false] {
        let fixture = coordinator_fixture(android_35_capabilities());
        let actual_on = policy(SplitTunnelMode::ExcludeSelected);
        let mut recorded_off = actual_on.clone();
        recorded_off.exclude_local_networks = false;
        recorded_off.policy_hash = format!("sha256:{}", "b".repeat(64));
        fixture
            .split_store
            .save(&StoredSplitTunnelState {
                cached_policy: Some(if cached_on {
                    actual_on.clone()
                } else {
                    recorded_off.clone()
                }),
                working_policy_hash: Some(recorded_off.policy_hash.clone()),
                previous_working_policy: Some(recorded_off.clone()),
                ..StoredSplitTunnelState::default()
            })
            .unwrap();
        let running = Connection {
            lease_id: "11111111-1111-4111-8111-111111111111".into(),
            session_id: None,
            pool_id: None,
            layer: Layer::Tic,
            transport_protocol: Default::default(),
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::ViaTak,
            egress_mode: EgressMode::Ipv4,
            probe_url: Some("https://1a.example.test/probe".into()),
            status: LeaseStatus::Connected,
            pinned: false,
            stopped_at: None,
        };
        fixture.api.set_bootstrap_connection(running.clone());
        // The native Android owner started cached ON outside this Core instance.
        let actual_options = EffectiveSplitTunnelPolicy::build(
            &actual_on,
            &installed(),
            android_35_capabilities(),
            Layer::Tic,
            RouteMode::ViaTak,
        )
        .unwrap()
        .options;
        assert!(actual_options.exclude_local_networks);
        fixture.tunnel.options.lock().unwrap().push(actual_options);
        fixture.tunnel.starts.store(1, Ordering::SeqCst);
        *fixture.tunnel.status.lock().unwrap() = TunnelStatus::Running;
        fixture.core.bootstrap(1_000).await.unwrap();
        let off_request = SplitTunnelSettingsUpdate {
            mode: recorded_off.mode,
            exclude_local_networks: false,
            selected_packages: Vec::new(),
        };
        assert!(fixture
            .core
            .split_tunnel_settings_require_reconnect(&off_request)
            .await
            .unwrap());
        fixture.api.set_policy(recorded_off.clone());
        fixture
            .core
            .save_split_tunnel_settings(&off_request, 1_100)
            .await
            .unwrap();
        assert!(
            !fixture
                .tunnel
                .options
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .exclude_local_networks
        );
        assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.api.stop_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.core.state().await.connection, Some(running));
        assert_eq!(
            fixture
                .api
                .apply_results
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .status,
            SplitTunnelApplyStatus::Applied
        );
    }
}

#[tokio::test]
async fn confirmed_unchanged_save_needs_no_single_lease_configuration() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(900, false)
        .await
        .unwrap();
    fixture
        .core
        .start(ConnectOptions::android_default(), 1_000)
        .await
        .unwrap();
    // Service-owned v2 sessions intentionally do not retain a legacy config.
    let mut stored = fixture.secret_store.load().unwrap().unwrap();
    stored.saved_connection = None;
    stored.pinned_connection = None;
    fixture.secret_store.save(&stored).unwrap();
    let initial = policy(SplitTunnelMode::ExcludeSelected);
    fixture
        .core
        .save_split_tunnel_settings(
            &SplitTunnelSettingsUpdate {
                mode: initial.mode,
                exclude_local_networks: initial.exclude_local_networks,
                selected_packages: Vec::new(),
            },
            1_100,
        )
        .await
        .unwrap();
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::Applied
    );
}

#[tokio::test]
async fn unchanged_domain_routes_do_not_require_reconnect_confirmation() {
    let fixture = coordinator_fixture(android_35_capabilities());
    let mut initial = policy(SplitTunnelMode::ExcludeSelected);
    initial.format_version = 2;
    initial.address_rules = vec![SplitTunnelAddressRule {
        id: 1,
        scope: SplitTunnelAddressRuleScope::ThisDevice,
        kind: SplitTunnelAddressRuleKind::Domain,
        value: "cached.example".into(),
    }];
    fixture
        .split_store
        .save(&StoredSplitTunnelState {
            cached_policy: Some(initial.clone()),
            domain_resolutions: vec![StoredSplitTunnelDomainResolution {
                domain: "cached.example".into(),
                ipv4_cidrs: vec!["198.51.100.9/32".into()],
                resolved_at_unix: 900,
            }],
            ..StoredSplitTunnelState::default()
        })
        .unwrap();
    fixture
        .core
        .start(ConnectOptions::android_default(), 1_000)
        .await
        .unwrap();
    assert!(fixture
        .tunnel
        .options
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .excluded_ipv4_cidrs
        .contains(&"198.51.100.9/32".to_string()));
    assert!(!fixture
        .core
        .split_tunnel_settings_require_reconnect(&SplitTunnelSettingsUpdate {
            mode: initial.mode,
            exclude_local_networks: initial.exclude_local_networks,
            selected_packages: Vec::new(),
        })
        .await
        .unwrap());
}

#[tokio::test]
async fn settings_save_keeps_preflight_domain_addresses_without_restart() {
    for retain_configuration in [true, false] {
        let fixture = coordinator_fixture(capabilities(TunnelPlatform::Linux, None, true, false));
        fixture
            .core
            .synchronize_split_tunnel(900, false)
            .await
            .unwrap();
        let running = fixture
            .core
            .start(ConnectOptions::android_default(), 1_000)
            .await
            .unwrap();
        let mut initial = policy(SplitTunnelMode::ExcludeSelected);
        initial.format_version = 2;
        // Numeric lookup deterministically returns 127.0.0.1, unlike the
        // last-good address used by the previous process and by preflight.
        initial.address_rules = vec![SplitTunnelAddressRule {
            id: 1,
            scope: SplitTunnelAddressRuleScope::ThisDevice,
            kind: SplitTunnelAddressRuleKind::Domain,
            value: "127.0.0.1".into(),
        }];
        fixture.api.set_policy(initial.clone());
        fixture
            .split_store
            .save(&StoredSplitTunnelState {
                cached_policy: Some(initial.clone()),
                working_policy_hash: Some(initial.policy_hash.clone()),
                domain_resolutions: vec![StoredSplitTunnelDomainResolution {
                    domain: "127.0.0.1".into(),
                    ipv4_cidrs: vec!["198.51.100.9/32".into()],
                    resolved_at_unix: 900,
                }],
                ..StoredSplitTunnelState::default()
            })
            .unwrap();
        fixture
            .tunnel
            .options
            .lock()
            .unwrap()
            .last_mut()
            .unwrap()
            .excluded_ipv4_cidrs
            .push("198.51.100.9/32".into());
        fixture.api.set_bootstrap_connection(running.clone());
        let restored = support::core_with_split(
            fixture.api.clone(),
            fixture.secret_store.clone(),
            fixture.split_store.clone(),
            fixture.tunnel.clone(),
            fixture.logger.clone(),
        );
        restored.bootstrap(1_050).await.unwrap();
        if !retain_configuration {
            // Clear after bootstrap so legacy recovery cannot refill it.
            let mut stored = fixture.secret_store.load().unwrap().unwrap();
            stored.saved_connection = None;
            stored.pinned_connection = None;
            fixture.secret_store.save(&stored).unwrap();
        }
        let request = same_split_settings();
        assert!(!restored
            .split_tunnel_settings_require_reconnect(&request)
            .await
            .unwrap());
        restored
            .save_split_tunnel_settings(&request, 1_100)
            .await
            .unwrap();
        assert_eq!(
            fixture.tunnel.starts.load(Ordering::SeqCst),
            1,
            "Save must use the same cached domain addresses as preflight"
        );
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.split_store.load().unwrap().domain_resolutions[0].ipv4_cidrs,
            vec!["198.51.100.9/32"]
        );
        assert_eq!(restored.state().await.connection, Some(running));
        if retain_configuration {
            // Domain refresh is still intentional during policy sync, rather
            // than being an unconfirmed side effect of settings Save.
            assert_eq!(
                restored
                    .synchronize_split_tunnel(1_150, true)
                    .await
                    .unwrap(),
                SplitTunnelSyncOutcome::Updated { reconnected: true }
            );
            assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
            assert!(fixture
                .tunnel
                .options
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .excluded_ipv4_cidrs
                .contains(&"127.0.0.1/32".into()));
        }
    }
}

#[tokio::test]
async fn unchanged_settings_save_defers_pending_domain_without_cached_addresses() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(900, false)
        .await
        .unwrap();
    let running = fixture
        .core
        .start(ConnectOptions::android_default(), 1_000)
        .await
        .unwrap();
    let working = policy(SplitTunnelMode::ExcludeSelected);
    let mut pending = working.clone();
    pending.format_version = 2;
    pending.policy_hash = format!("sha256:{}", "b".repeat(64));
    pending.address_rules = vec![SplitTunnelAddressRule {
        id: 1,
        scope: SplitTunnelAddressRuleScope::ThisDevice,
        kind: SplitTunnelAddressRuleKind::Domain,
        value: "127.0.0.1".into(),
    }];
    // Persisted state after a new domain's lookup failed: previous policy
    // remains live. A fresh numeric lookup would now succeed deterministically.
    fixture
        .split_store
        .save(&StoredSplitTunnelState {
            cached_policy: Some(pending.clone()),
            working_policy_hash: Some(working.policy_hash.clone()),
            previous_working_policy: Some(working.clone()),
            failed_policy_hash: Some(pending.policy_hash.clone()),
            failed_policy_retry_after_unix: Some(5_000),
            ..StoredSplitTunnelState::default()
        })
        .unwrap();
    fixture.api.set_policy(pending.clone());
    let request = same_split_settings();
    assert!(!fixture
        .core
        .split_tunnel_settings_require_reconnect(&request)
        .await
        .unwrap());
    let reports = fixture.api.apply_results.lock().unwrap().len();
    fixture
        .core
        .save_split_tunnel_settings(&request, 1_100)
        .await
        .unwrap();
    assert_eq!(
        fixture.tunnel.starts.load(Ordering::SeqCst),
        1,
        "Save must not resolve a cache miss and replace unconfirmed routes"
    );
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    let state = fixture.split_store.load().unwrap();
    assert!(state.domain_resolutions.is_empty());
    assert_eq!(state.working_policy_hash, Some(working.policy_hash));
    assert_eq!(state.failed_policy_hash, Some(pending.policy_hash));
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_domain_resolution_unavailable")
    );
    assert_eq!(
        fixture.api.apply_results.lock().unwrap().len(),
        reports,
        "a deferred policy must not be reported as applied"
    );
    assert_eq!(fixture.core.state().await.connection, Some(running));
    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_150, true)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: true }
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
    assert!(fixture
        .tunnel
        .options
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .excluded_ipv4_cidrs
        .contains(&"127.0.0.1/32".into()));
}

#[tokio::test]
async fn settings_save_defers_when_previous_domain_plan_cannot_be_reconstructed() {
    for failed_starts in [0, 1] {
        let fixture = coordinator_fixture(android_35_capabilities());
        fixture
            .core
            .synchronize_split_tunnel(900, false)
            .await
            .unwrap();
        let running = fixture
            .core
            .start(ConnectOptions::android_default(), 1_000)
            .await
            .unwrap();
        let mut previous = policy(SplitTunnelMode::ExcludeSelected);
        previous.format_version = 2;
        previous.address_rules = vec![SplitTunnelAddressRule {
            id: 1,
            scope: SplitTunnelAddressRuleScope::ThisDevice,
            kind: SplitTunnelAddressRuleKind::Domain,
            value: "missing-working-cache.invalid".into(),
        }];
        // An independently running owner retains the old domain route, but
        // restoration cannot reconstruct it after the resolution cache is lost.
        let mut native_previous = fixture
            .tunnel
            .options
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        native_previous
            .excluded_ipv4_cidrs
            .push("198.51.100.9/32".into());
        *fixture.tunnel.options.lock().unwrap().last_mut().unwrap() = native_previous.clone();
        fixture
            .split_store
            .save(&StoredSplitTunnelState {
                cached_policy: Some(previous.clone()),
                working_policy_hash: Some(previous.policy_hash.clone()),
                ..StoredSplitTunnelState::default()
            })
            .unwrap();
        fixture.api.set_bootstrap_connection(running.clone());
        let restored = support::core_with_split(
            fixture.api.clone(),
            fixture.secret_store.clone(),
            fixture.split_store.clone(),
            fixture.tunnel.clone(),
            fixture.logger.clone(),
        );
        restored.bootstrap(1_050).await.unwrap();
        assert_eq!(restored.state().await.phase, Phase::Connected);
        assert_eq!(
            restored.split_tunnel_warning().await.as_deref(),
            Some("split_tunnel_domain_resolution_unavailable")
        );
        let mut proposed = policy(SplitTunnelMode::ExcludeSelected);
        proposed.policy_hash = format!("sha256:{}", "b".repeat(64));
        proposed.exclude_local_networks = false;
        fixture.api.set_policy(proposed.clone());
        fixture
            .tunnel
            .fail_next_starts
            .store(failed_starts, Ordering::SeqCst);
        let reports = fixture.api.apply_results.lock().unwrap().len();
        let request = SplitTunnelSettingsUpdate {
            mode: proposed.mode,
            exclude_local_networks: false,
            selected_packages: Vec::new(),
        };
        let result = restored.save_split_tunnel_settings(&request, 1_100).await;
        assert_eq!(
            fixture.tunnel.starts.load(Ordering::SeqCst),
            1,
            "missing rollback routes must defer replacement, not use default options"
        );
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(result.unwrap(), proposed);
        assert_eq!(
            fixture.tunnel.options.lock().unwrap().last(),
            Some(&native_previous)
        );
        let stored = fixture.split_store.load().unwrap();
        assert_eq!(stored.working_policy_hash, Some(previous.policy_hash));
        assert_eq!(stored.cached_policy, Some(proposed.clone()));
        assert_eq!(stored.failed_policy_hash, Some(proposed.policy_hash));
        assert_eq!(
            fixture.api.apply_results.lock().unwrap().len(),
            reports,
            "deferred replacement must not report Applied or RolledBack"
        );
        assert_eq!(
            restored.split_tunnel_warning().await.as_deref(),
            Some("split_tunnel_domain_resolution_unavailable")
        );
        assert_eq!(restored.state().await.connection, Some(running));
    }
}

#[tokio::test]
async fn settings_noop_keeps_dispatched_dns_for_local_recovery() {
    for capabilities in [
        android_35_capabilities(),
        capabilities(TunnelPlatform::Android, Some(32), true, true),
        capabilities(TunnelPlatform::Linux, None, true, false),
    ] {
        let fixture = coordinator_fixture(capabilities);
        let dns_a = vec!["9.9.9.9".parse().unwrap()];
        fixture.core.set_dns_servers(dns_a.clone());
        fixture
            .core
            .synchronize_split_tunnel(900, false)
            .await
            .unwrap();
        let running = fixture
            .core
            .start(ConnectOptions::android_default(), 1_000)
            .await
            .unwrap();
        fixture
            .core
            .set_dns_servers(vec!["8.8.8.8".parse().unwrap()]);
        let mut updated = policy(SplitTunnelMode::ExcludeSelected);
        updated.policy_hash = format!("sha256:{}", "b".repeat(64));
        fixture.api.set_policy(updated.clone());
        let request = same_split_settings();
        assert!(!fixture
            .core
            .split_tunnel_settings_require_reconnect(&request)
            .await
            .unwrap());
        fixture
            .core
            .save_split_tunnel_settings(&request, 1_100)
            .await
            .unwrap();
        assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.split_store.load().unwrap().working_policy_hash,
            Some(updated.policy_hash)
        );
        assert_eq!(
            fixture
                .tunnel
                .options
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .dns_servers,
            dns_a
        );
        assert_eq!(
            fixture
                .core
                .recover_stalled_data_plane(
                    &running.lease_id,
                    StalledDataPlaneRecovery::RestartLocalTunnel,
                )
                .await
                .unwrap(),
            StalledDataPlaneRecoveryOutcome::Reconnected
        );
        assert_eq!(
            fixture
                .tunnel
                .options
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .dns_servers,
            dns_a,
            "recovery must retain the DNS dispatched on Start, not an unapplied preference"
        );
    }
}

#[tokio::test]
async fn settings_noop_keeps_dispatched_options_for_rollback() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .set_dns_servers(vec!["9.9.9.9".parse().unwrap()]);
    fixture
        .core
        .synchronize_split_tunnel(900, false)
        .await
        .unwrap();
    let running = fixture
        .core
        .start(ConnectOptions::android_default(), 1_000)
        .await
        .unwrap();
    let original = fixture
        .tunnel
        .options
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    fixture
        .core
        .set_dns_servers(vec!["8.8.8.8".parse().unwrap()]);
    let mut same_routes = policy(SplitTunnelMode::ExcludeSelected);
    same_routes.policy_hash = format!("sha256:{}", "b".repeat(64));
    fixture.api.set_policy(same_routes);
    fixture
        .core
        .save_split_tunnel_settings(&same_split_settings(), 1_100)
        .await
        .unwrap();
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
    let mut replacement = policy(SplitTunnelMode::ExcludeSelected);
    replacement.policy_hash = format!("sha256:{}", "c".repeat(64));
    replacement.exclude_local_networks = false;
    fixture.api.set_policy(replacement);
    fixture.tunnel.fail_next_starts.store(1, Ordering::SeqCst);
    let request = SplitTunnelSettingsUpdate {
        mode: SplitTunnelMode::ExcludeSelected,
        exclude_local_networks: false,
        selected_packages: Vec::new(),
    };
    assert!(
        matches!(fixture.core.save_split_tunnel_settings(&request, 1_200).await,
        Err(CoreError::SplitTunnel(code)) if code == "split_tunnel_apply_failed")
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 3);
    assert_eq!(
        fixture.tunnel.options.lock().unwrap().last(),
        Some(&original),
        "rollback must retain all dispatched options, including DNS and native policy hash"
    );
    assert_eq!(fixture.core.state().await.connection, Some(running));
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::RolledBack
    );
}

#[tokio::test]
async fn restored_api32_settings_save_does_not_replace_inactive_split_policy() {
    for retain_configuration in [true, false] {
        let fixture =
            coordinator_fixture(capabilities(TunnelPlatform::Android, Some(32), true, true));
        fixture
            .core
            .set_dns_servers(vec!["9.9.9.9".parse().unwrap()]);
        fixture
            .core
            .synchronize_split_tunnel(900, false)
            .await
            .unwrap();
        let running = fixture
            .core
            .start(ConnectOptions::android_default(), 1_000)
            .await
            .unwrap();
        assert_eq!(
            *fixture.tunnel.options.lock().unwrap().last().unwrap(),
            TunnelOptions {
                dns_servers: vec!["9.9.9.9".parse().unwrap()],
                ..TunnelOptions::default()
            }
        );
        fixture.api.set_bootstrap_connection(running.clone());
        let restored = support::core_with_split(
            fixture.api.clone(),
            fixture.secret_store.clone(),
            fixture.split_store.clone(),
            fixture.tunnel.clone(),
            fixture.logger.clone(),
        );
        restored.set_dns_servers(vec!["9.9.9.9".parse().unwrap()]);
        restored.bootstrap(1_050).await.unwrap();
        if !retain_configuration {
            let mut stored = fixture.secret_store.load().unwrap().unwrap();
            stored.saved_connection = None;
            stored.pinned_connection = None;
            fixture.secret_store.save(&stored).unwrap();
        }
        let mut request = same_split_settings();
        request.exclude_local_networks = false;
        assert!(
            !restored
                .split_tunnel_settings_require_reconnect(&request)
                .await
                .unwrap(),
            "Android API32 ignores split options even after bootstrap"
        );
        let mut updated = policy(request.mode);
        updated.exclude_local_networks = false;
        updated.policy_hash = format!("sha256:{}", "b".repeat(64));
        fixture.api.set_policy(updated.clone());
        assert_eq!(
            restored
                .save_split_tunnel_settings(&request, 1_100)
                .await
                .unwrap(),
            updated
        );
        assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(restored.state().await.connection, Some(running));
        assert_eq!(
            fixture.split_store.load().unwrap().working_policy_hash,
            Some(updated.policy_hash)
        );
    }
}

#[tokio::test]
async fn restored_stall_restart_and_retry_confirm_dispatched_split_options() {
    for failed_starts in [0, 1] {
        let fixture = coordinator_fixture(android_35_capabilities());
        fixture
            .core
            .synchronize_split_tunnel(900, false)
            .await
            .unwrap();
        let running = fixture
            .core
            .start(ConnectOptions::android_default(), 1_000)
            .await
            .unwrap();
        fixture.api.set_bootstrap_connection(running.clone());
        let restored = support::core_with_split(
            fixture.api.clone(),
            fixture.secret_store.clone(),
            fixture.split_store.clone(),
            fixture.tunnel.clone(),
            fixture.logger.clone(),
        );
        restored.bootstrap(1_050).await.unwrap();
        let request = same_split_settings();
        assert!(restored
            .split_tunnel_settings_require_reconnect(&request)
            .await
            .unwrap());
        fixture
            .tunnel
            .fail_next_starts
            .store(failed_starts, Ordering::SeqCst);
        assert_eq!(
            restored
                .recover_stalled_data_plane(
                    &running.lease_id,
                    StalledDataPlaneRecovery::RestartLocalTunnel
                )
                .await
                .unwrap(),
            StalledDataPlaneRecoveryOutcome::Reconnected
        );
        assert!(
            !restored
                .split_tunnel_settings_require_reconnect(&request)
                .await
                .unwrap(),
            "a successful exact-options restart must confirm the live plan"
        );
        restored
            .save_split_tunnel_settings(&request, 1_100)
            .await
            .unwrap();
        assert_eq!(
            fixture.tunnel.starts.load(Ordering::SeqCst),
            2 + failed_starts
        );
    }
}

#[tokio::test]
async fn restored_network_restart_and_retry_confirm_dispatched_split_options() {
    for failed_starts in [0, 1] {
        let fixture = coordinator_fixture(android_35_capabilities());
        fixture.tunnel.set_fingerprints(["network-a"]);
        fixture
            .core
            .synchronize_split_tunnel(900, false)
            .await
            .unwrap();
        let running = fixture
            .core
            .start(ConnectOptions::android_default(), 1_000)
            .await
            .unwrap();
        fixture.api.set_bootstrap_connection(running.clone());
        let restored = support::core_with_split(
            fixture.api.clone(),
            fixture.secret_store.clone(),
            fixture.split_store.clone(),
            fixture.tunnel.clone(),
            fixture.logger.clone(),
        );
        restored.bootstrap(1_050).await.unwrap();
        let request = same_split_settings();
        assert!(restored
            .split_tunnel_settings_require_reconnect(&request)
            .await
            .unwrap());
        fixture.tunnel.set_fingerprints(["network-b", "network-b"]);
        assert_eq!(
            restored.poll_physical_network(1_100).await.unwrap(),
            PhysicalNetworkPollOutcome::ChangePending
        );
        fixture
            .tunnel
            .fail_next_starts
            .store(failed_starts, Ordering::SeqCst);
        assert_eq!(
            restored.poll_physical_network(1_130).await.unwrap(),
            PhysicalNetworkPollOutcome::Reconnected
        );
        assert!(
            !restored
                .split_tunnel_settings_require_reconnect(&request)
                .await
                .unwrap(),
            "network recovery must confirm the options actually dispatched"
        );
        restored
            .save_split_tunnel_settings(&request, 1_150)
            .await
            .unwrap();
        assert_eq!(
            fixture.tunnel.starts.load(Ordering::SeqCst),
            2 + failed_starts
        );
    }
}

#[tokio::test]
async fn unsupported_rebind_does_not_confirm_restored_split_options() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(900, false)
        .await
        .unwrap();
    let running = fixture
        .core
        .start(ConnectOptions::android_default(), 1_000)
        .await
        .unwrap();
    fixture.api.set_bootstrap_connection(running.clone());
    let restored = support::core_with_split(
        fixture.api.clone(),
        fixture.secret_store.clone(),
        fixture.split_store.clone(),
        fixture.tunnel.clone(),
        fixture.logger.clone(),
    );
    restored.bootstrap(1_050).await.unwrap();
    assert_eq!(
        restored
            .recover_stalled_data_plane(&running.lease_id, StalledDataPlaneRecovery::RebindUdp)
            .await
            .unwrap(),
        StalledDataPlaneRecoveryOutcome::Unsupported
    );
    assert!(restored
        .split_tunnel_settings_require_reconnect(&same_split_settings())
        .await
        .unwrap());
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
}

fn same_split_settings() -> SplitTunnelSettingsUpdate {
    let initial = policy(SplitTunnelMode::ExcludeSelected);
    SplitTunnelSettingsUpdate {
        mode: initial.mode,
        exclude_local_networks: initial.exclude_local_networks,
        selected_packages: Vec::new(),
    }
}

#[tokio::test]
async fn restored_android33_or_unknown_api_still_requires_confirmed_native_plan() {
    for api_level in [Some(33), None] {
        let fixture =
            coordinator_fixture(capabilities(TunnelPlatform::Android, api_level, true, true));
        fixture
            .core
            .synchronize_split_tunnel(900, false)
            .await
            .unwrap();
        let running = fixture
            .core
            .start(ConnectOptions::android_default(), 1_000)
            .await
            .unwrap();
        fixture.api.set_bootstrap_connection(running);
        let restored = support::core_with_split(
            fixture.api.clone(),
            fixture.secret_store.clone(),
            fixture.split_store.clone(),
            fixture.tunnel.clone(),
            fixture.logger.clone(),
        );
        restored.bootstrap(1_050).await.unwrap();
        let mut stored = fixture.secret_store.load().unwrap().unwrap();
        stored.saved_connection = None;
        stored.pinned_connection = None;
        fixture.secret_store.save(&stored).unwrap();
        assert!(restored
            .split_tunnel_settings_require_reconnect(&same_split_settings())
            .await
            .unwrap());
        assert!(matches!(
            restored
                .save_split_tunnel_settings(&same_split_settings(), 1_100)
                .await
                .unwrap_err(),
            CoreError::SplitTunnel(code) if code == "split_tunnel_saved_connection_unavailable"
        ));
        assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn failed_recovery_does_not_confirm_restored_split_options() {
    for network_recovery in [true, false] {
        let fixture = coordinator_fixture(android_35_capabilities());
        fixture.tunnel.set_fingerprints(["network-a"]);
        fixture
            .core
            .synchronize_split_tunnel(900, false)
            .await
            .unwrap();
        let running = fixture
            .core
            .start(ConnectOptions::android_default(), 1_000)
            .await
            .unwrap();
        fixture.api.set_bootstrap_connection(running.clone());
        let restored = support::core_with_split(
            fixture.api.clone(),
            fixture.secret_store.clone(),
            fixture.split_store.clone(),
            fixture.tunnel.clone(),
            fixture.logger.clone(),
        );
        restored.bootstrap(1_050).await.unwrap();
        fixture.tunnel.fail_next_starts.store(2, Ordering::SeqCst);
        if network_recovery {
            fixture.tunnel.set_fingerprints(["network-b", "network-b"]);
            assert_eq!(
                restored.poll_physical_network(1_100).await.unwrap(),
                PhysicalNetworkPollOutcome::ChangePending
            );
            assert_eq!(
                restored.poll_physical_network(1_130).await.unwrap(),
                PhysicalNetworkPollOutcome::ReconnectFailed
            );
        } else {
            assert!(restored
                .recover_stalled_data_plane(
                    &running.lease_id,
                    StalledDataPlaneRecovery::RestartLocalTunnel
                )
                .await
                .is_err());
        }
        // An independently running owner can be rediscovered by bootstrap,
        // but a failed local restart must not have attested its options.
        *fixture.tunnel.status.lock().unwrap() = TunnelStatus::Running;
        restored.bootstrap(1_150).await.unwrap();
        assert!(restored
            .split_tunnel_settings_require_reconnect(&same_split_settings())
            .await
            .unwrap());
    }
}

#[tokio::test]
async fn failed_recovery_retires_confirmation_of_the_previous_native_instance() {
    for network_recovery in [true, false] {
        let fixture = coordinator_fixture(android_35_capabilities());
        fixture.tunnel.set_fingerprints(["network-a"]);
        fixture
            .core
            .synchronize_split_tunnel(900, false)
            .await
            .unwrap();
        let running = fixture
            .core
            .start(ConnectOptions::android_default(), 1_000)
            .await
            .unwrap();
        assert!(!fixture
            .core
            .split_tunnel_settings_require_reconnect(&same_split_settings())
            .await
            .unwrap());
        fixture.tunnel.fail_next_starts.store(2, Ordering::SeqCst);
        if network_recovery {
            fixture.tunnel.set_fingerprints(["network-b", "network-b"]);
            assert_eq!(
                fixture.core.poll_physical_network(1_100).await.unwrap(),
                PhysicalNetworkPollOutcome::ChangePending
            );
            assert_eq!(
                fixture.core.poll_physical_network(1_130).await.unwrap(),
                PhysicalNetworkPollOutcome::ReconnectFailed
            );
        } else {
            assert!(fixture
                .core
                .recover_stalled_data_plane(
                    &running.lease_id,
                    StalledDataPlaneRecovery::RestartLocalTunnel
                )
                .await
                .is_err());
        }
        // Bootstrap rediscovers an independently started owner with the same
        // lease/epoch but different native routes. The old Start is no proof.
        fixture
            .tunnel
            .options
            .lock()
            .unwrap()
            .last_mut()
            .unwrap()
            .exclude_local_networks = false;
        *fixture.tunnel.status.lock().unwrap() = TunnelStatus::Running;
        fixture.api.set_bootstrap_connection(running.clone());
        fixture.core.bootstrap(1_150).await.unwrap();
        assert!(
            fixture
                .core
                .split_tunnel_settings_require_reconnect(&same_split_settings())
                .await
                .unwrap(),
            "a destroyed native instance must not retain confirmation after failed recovery"
        );
        let starts = fixture.tunnel.starts.load(Ordering::SeqCst);
        fixture
            .core
            .save_split_tunnel_settings(&same_split_settings(), 1_200)
            .await
            .unwrap();
        assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), starts + 1);
        assert!(
            fixture
                .tunnel
                .options
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .exclude_local_networks
        );
    }
}

#[tokio::test]
async fn failed_restoration_cannot_reuse_a_retired_owners_rollback_options() {
    for changed_lease in [true, false] {
        let fixture = coordinator_fixture(android_35_capabilities());
        fixture
            .core
            .set_dns_servers(vec!["9.9.9.9".parse().unwrap()]);
        fixture
            .core
            .synchronize_split_tunnel(900, false)
            .await
            .unwrap();
        let mut running = fixture
            .core
            .start(ConnectOptions::android_default(), 1_000)
            .await
            .unwrap();
        if changed_lease {
            running.lease_id = "22222222-2222-4222-8222-222222222222".into();
        } else {
            fixture.core.signal_start_cancellation();
        }
        let mut auth = fixture.secret_store.load().unwrap().unwrap();
        auth.saved_connection.as_mut().unwrap().lease_id = running.lease_id.clone();
        fixture.secret_store.save(&auth).unwrap();
        let mut previous = policy(SplitTunnelMode::ExcludeSelected);
        previous.format_version = 2;
        previous.policy_hash = format!("sha256:{}", "b".repeat(64));
        previous.address_rules = vec![SplitTunnelAddressRule {
            id: 1,
            scope: SplitTunnelAddressRuleScope::ThisDevice,
            kind: SplitTunnelAddressRuleKind::Domain,
            value: "missing-current-owner.invalid".into(),
        }];
        fixture
            .split_store
            .save(&StoredSplitTunnelState {
                cached_policy: Some(previous.clone()),
                working_policy_hash: Some(previous.policy_hash.clone()),
                ..StoredSplitTunnelState::default()
            })
            .unwrap();
        // Model a different live native owner, not a new Core Start. Its old
        // domain route cannot be inferred from the retired owner's options.
        let mut native_current = fixture
            .tunnel
            .options
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        native_current.excluded_ipv4_cidrs = vec!["198.51.100.9/32".into()];
        native_current.dns_servers = vec!["8.8.8.8".parse().unwrap()];
        *fixture.tunnel.options.lock().unwrap().last_mut().unwrap() = native_current.clone();
        fixture.api.set_bootstrap_connection(running.clone());
        fixture.core.bootstrap(1_050).await.unwrap();
        assert_eq!(
            fixture.core.split_tunnel_warning().await.as_deref(),
            Some("split_tunnel_domain_resolution_unavailable")
        );
        let mut proposed = policy(SplitTunnelMode::ExcludeSelected);
        proposed.policy_hash = format!("sha256:{}", "c".repeat(64));
        proposed.exclude_local_networks = false;
        fixture.api.set_policy(proposed.clone());
        fixture.tunnel.fail_next_starts.store(1, Ordering::SeqCst);
        let reports = fixture.api.apply_results.lock().unwrap().len();
        fixture
            .core
            .save_split_tunnel_settings(
                &SplitTunnelSettingsUpdate {
                    mode: proposed.mode,
                    exclude_local_networks: false,
                    selected_packages: Vec::new(),
                },
                1_100,
            )
            .await
            .unwrap();
        assert_eq!(
            fixture.tunnel.starts.load(Ordering::SeqCst),
            1,
            "unknown current-owner routes must not be replaced or rolled back from a retired owner"
        );
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture.tunnel.options.lock().unwrap().last(),
            Some(&native_current)
        );
        assert_eq!(
            fixture.split_store.load().unwrap().working_policy_hash,
            Some(previous.policy_hash)
        );
        assert_eq!(fixture.api.apply_results.lock().unwrap().len(), reports);
        assert_eq!(fixture.core.state().await.connection, Some(running));
    }
}

#[tokio::test]
async fn recovery_plan_unavailable_after_restoration_defers_until_cache_is_repaired() {
    for changed_lease in [true, false] {
        let fixture = coordinator_fixture(android_35_capabilities());
        fixture
            .core
            .set_dns_servers(vec!["9.9.9.9".parse().unwrap()]);
        fixture
            .core
            .synchronize_split_tunnel(900, false)
            .await
            .unwrap();
        let mut running = fixture
            .core
            .start(ConnectOptions::android_default(), 1_000)
            .await
            .unwrap();
        if changed_lease {
            running.lease_id = "22222222-2222-4222-8222-222222222222".into();
        } else {
            fixture.core.signal_start_cancellation();
        }
        let mut auth = fixture.secret_store.load().unwrap().unwrap();
        auth.saved_connection.as_mut().unwrap().lease_id = running.lease_id.clone();
        fixture.secret_store.save(&auth).unwrap();
        let mut previous = policy(SplitTunnelMode::ExcludeSelected);
        previous.format_version = 2;
        previous.policy_hash = format!("sha256:{}", "b".repeat(64));
        previous.address_rules = vec![SplitTunnelAddressRule {
            id: 1,
            scope: SplitTunnelAddressRuleScope::ThisDevice,
            kind: SplitTunnelAddressRuleKind::Domain,
            value: "missing-current-owner.invalid".into(),
        }];
        fixture
            .split_store
            .save(&StoredSplitTunnelState {
                cached_policy: Some(previous.clone()),
                working_policy_hash: Some(previous.policy_hash.clone()),
                ..StoredSplitTunnelState::default()
            })
            .unwrap();
        let mut actual = fixture
            .tunnel
            .options
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        actual.excluded_ipv4_cidrs = vec!["198.51.100.9/32".into()];
        *fixture.tunnel.options.lock().unwrap().last_mut().unwrap() = actual.clone();
        fixture.api.set_bootstrap_connection(running.clone());
        fixture.core.bootstrap(1_050).await.unwrap();
        assert_eq!(fixture.core.state().await.phase, Phase::Connected);
        assert_eq!(
            fixture.core.split_tunnel_warning().await.as_deref(),
            Some("split_tunnel_domain_resolution_unavailable")
        );
        let outcome = fixture
            .core
            .recover_stalled_data_plane(
                &running.lease_id,
                StalledDataPlaneRecovery::RestartLocalTunnel,
            )
            .await
            .unwrap();
        assert_eq!(
            fixture.tunnel.starts.load(Ordering::SeqCst),
            1,
            "unavailable current-owner options must not dispatch placeholder routes/DNS"
        );
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(outcome, StalledDataPlaneRecoveryOutcome::Skipped);
        assert_eq!(fixture.tunnel.options.lock().unwrap().last(), Some(&actual));
        assert_eq!(fixture.core.state().await.connection, Some(running.clone()));
        assert_eq!(fixture.core.state().await.phase, Phase::Connected);
        assert_eq!(
            fixture.core.split_tunnel_warning().await.as_deref(),
            Some("split_tunnel_domain_resolution_unavailable")
        );

        // A later ordinary bootstrap can reconstruct a usable plan from a
        // repaired cache; deferral must not disable all future local recovery.
        let mut repaired = fixture.split_store.load().unwrap();
        repaired.domain_resolutions = vec![StoredSplitTunnelDomainResolution {
            domain: "missing-current-owner.invalid".into(),
            ipv4_cidrs: vec!["198.51.100.9/32".into()],
            resolved_at_unix: 1_100,
        }];
        fixture.split_store.save(&repaired).unwrap();
        fixture.core.bootstrap(1_150).await.unwrap();
        assert_eq!(
            fixture
                .core
                .recover_stalled_data_plane(
                    &running.lease_id,
                    StalledDataPlaneRecovery::RestartLocalTunnel,
                )
                .await
                .unwrap(),
            StalledDataPlaneRecoveryOutcome::Reconnected
        );
        let restored = fixture
            .tunnel
            .options
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert!(restored
            .excluded_ipv4_cidrs
            .contains(&"198.51.100.9/32".into()));
        assert_eq!(
            restored.dns_servers,
            vec!["9.9.9.9".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(restored.policy_hash, Some(previous.policy_hash));
        assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
    }
}

async fn unavailable_domain_recipe_with_repaired_cache(
) -> (CoordinatorFixture, Connection, SplitTunnelPolicy) {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .set_dns_servers(vec!["9.9.9.9".parse().unwrap()]);
    let mut previous = policy(SplitTunnelMode::ExcludeSelected);
    previous.format_version = 2;
    previous.policy_hash = format!("sha256:{}", "b".repeat(64));
    previous.address_rules = vec![SplitTunnelAddressRule {
        id: 1,
        scope: SplitTunnelAddressRuleScope::ThisDevice,
        kind: SplitTunnelAddressRuleKind::Domain,
        value: "rollback-domain.invalid".into(),
    }];
    let cached_address = StoredSplitTunnelDomainResolution {
        domain: "rollback-domain.invalid".into(),
        ipv4_cidrs: vec!["198.51.100.9/32".into()],
        resolved_at_unix: 900,
    };
    fixture
        .split_store
        .save(&StoredSplitTunnelState {
            cached_policy: Some(previous.clone()),
            domain_resolutions: vec![cached_address.clone()],
            ..StoredSplitTunnelState::default()
        })
        .unwrap();
    let running = fixture
        .core
        .start(ConnectOptions::android_default(), 1_000)
        .await
        .unwrap();
    assert!(fixture
        .tunnel
        .options
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .excluded_ipv4_cidrs
        .contains(&"198.51.100.9/32".into()));

    // Restoration retires the old epoch's recipe, then fails because the
    // persistent cache is temporarily missing. The native tunnel stays up.
    fixture.core.signal_start_cancellation();
    let mut state = fixture.split_store.load().unwrap();
    state.domain_resolutions.clear();
    fixture.split_store.save(&state).unwrap();
    fixture.api.set_bootstrap_connection(running.clone());
    fixture.core.bootstrap(1_050).await.unwrap();
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_domain_resolution_unavailable")
    );

    // Save, not another bootstrap, is the next consumer of repaired addresses.
    let mut state = fixture.split_store.load().unwrap();
    state.domain_resolutions = vec![cached_address];
    fixture.split_store.save(&state).unwrap();
    (fixture, running, previous)
}

#[tokio::test]
async fn settings_save_preserves_rollback_cache_until_new_domain_plan_is_applied() {
    for disable_split in [false, true] {
        let (fixture, running, previous) = unavailable_domain_recipe_with_repaired_cache().await;
        let mut proposed = previous;
        proposed.policy_hash = format!("sha256:{}", "c".repeat(64));
        proposed.exclude_local_networks = false;
        proposed.address_rules.clear();
        proposed.enabled = !disable_split;
        fixture.api.set_policy(proposed.clone());
        let result = fixture
            .core
            .save_split_tunnel_settings(
                &SplitTunnelSettingsUpdate {
                    mode: proposed.mode,
                    exclude_local_networks: false,
                    selected_packages: Vec::new(),
                },
                1_150,
            )
            .await
            .unwrap();

        assert_eq!(
            fixture.tunnel.starts.load(Ordering::SeqCst),
            2,
            "proposed policy must not erase available rollback addresses before native apply"
        );
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
        assert_eq!(result, proposed);
        let native = fixture
            .tunnel
            .options
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert!(!native
            .excluded_ipv4_cidrs
            .contains(&"198.51.100.9/32".into()));
        let state = fixture.split_store.load().unwrap();
        assert!(
            state.domain_resolutions.is_empty(),
            "obsolete cache is pruned after successful apply"
        );
        assert_eq!(state.working_policy_hash, Some(proposed.policy_hash));
        assert!(state.failed_policy_hash.is_none());
        assert_eq!(fixture.core.state().await.connection, Some(running));
        assert_eq!(
            fixture
                .api
                .apply_results
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .status,
            SplitTunnelApplyStatus::Applied
        );
    }
}

#[tokio::test]
async fn settings_save_restores_old_domain_cache_after_native_apply_rollback() {
    for disable_split in [false, true] {
        let (fixture, running, previous) = unavailable_domain_recipe_with_repaired_cache().await;
        let old_native = fixture
            .tunnel
            .options
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        let old_cache = fixture.split_store.load().unwrap().domain_resolutions;
        let mut proposed = previous.clone();
        proposed.policy_hash = format!("sha256:{}", "c".repeat(64));
        proposed.exclude_local_networks = false;
        proposed.address_rules.clear();
        proposed.enabled = !disable_split;
        fixture.api.set_policy(proposed.clone());
        fixture.tunnel.fail_next_starts.store(1, Ordering::SeqCst);
        let error = fixture
            .core
            .save_split_tunnel_settings(
                &SplitTunnelSettingsUpdate {
                    mode: proposed.mode,
                    exclude_local_networks: false,
                    selected_packages: Vec::new(),
                },
                1_150,
            )
            .await
            .unwrap_err();

        assert!(
            matches!(error, CoreError::SplitTunnel(ref code) if code == "split_tunnel_apply_failed")
        );
        assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 3);
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.tunnel.options.lock().unwrap().last(),
            Some(&old_native)
        );
        let state = fixture.split_store.load().unwrap();
        assert_eq!(
            state.domain_resolutions, old_cache,
            "rollback must retain the restored working plan's cache"
        );
        assert_eq!(state.working_policy_hash, Some(previous.policy_hash));
        assert_eq!(state.failed_policy_hash, Some(proposed.policy_hash));
        assert_eq!(fixture.core.state().await.connection, Some(running));
        assert_eq!(fixture.core.state().await.phase, Phase::Connected);
        assert_eq!(
            fixture
                .api
                .apply_results
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .status,
            SplitTunnelApplyStatus::RolledBack
        );
    }
}

#[tokio::test]
async fn settings_save_missing_new_domain_keeps_existing_rollback_cache() {
    let (fixture, running, previous) = unavailable_domain_recipe_with_repaired_cache().await;
    let old_native = fixture
        .tunnel
        .options
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    let old_cache = fixture.split_store.load().unwrap().domain_resolutions;
    let mut proposed = previous.clone();
    proposed.policy_hash = format!("sha256:{}", "c".repeat(64));
    proposed.address_rules[0].value = "new-domain-without-cache.invalid".into();
    fixture.api.set_policy(proposed.clone());
    fixture
        .core
        .save_split_tunnel_settings(
            &SplitTunnelSettingsUpdate {
                mode: proposed.mode,
                exclude_local_networks: true,
                selected_packages: Vec::new(),
            },
            1_150,
        )
        .await
        .unwrap();

    assert_eq!(
        fixture.split_store.load().unwrap().domain_resolutions,
        old_cache,
        "failed proposed-plan preparation must not consume the working plan's cached addresses"
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.tunnel.options.lock().unwrap().last(),
        Some(&old_native)
    );
    assert_eq!(fixture.core.state().await.connection, Some(running));
    assert_eq!(
        fixture.split_store.load().unwrap().working_policy_hash,
        Some(previous.policy_hash)
    );
    assert_eq!(
        fixture.split_store.load().unwrap().failed_policy_hash,
        Some(proposed.policy_hash)
    );
}

#[tokio::test]
async fn recovery_plan_from_a_retired_epoch_is_not_reused_before_bootstrap() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(900, false)
        .await
        .unwrap();
    let running = fixture
        .core
        .start(ConnectOptions::android_default(), 1_000)
        .await
        .unwrap();
    fixture.core.signal_start_cancellation();
    let outcome = fixture
        .core
        .recover_stalled_data_plane(
            &running.lease_id,
            StalledDataPlaneRecovery::RestartLocalTunnel,
        )
        .await
        .unwrap();
    assert_eq!(
        fixture.tunnel.starts.load(Ordering::SeqCst),
        1,
        "a new cancellation epoch must not reuse the retired owner's plan"
    );
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert_eq!(outcome, StalledDataPlaneRecoveryOutcome::Skipped);
}

#[tokio::test]
async fn recovery_plan_genuine_default_options_remain_recoverable_after_bootstrap() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Android, Some(32), true, true));
    fixture
        .core
        .synchronize_split_tunnel(900, false)
        .await
        .unwrap();
    let running = fixture
        .core
        .start(ConnectOptions::android_default(), 1_000)
        .await
        .unwrap();
    assert_eq!(
        fixture.tunnel.options.lock().unwrap().last(),
        Some(&TunnelOptions::default())
    );
    fixture.api.set_bootstrap_connection(running.clone());
    let restored = support::core_with_split(
        fixture.api.clone(),
        fixture.secret_store.clone(),
        fixture.split_store.clone(),
        fixture.tunnel.clone(),
        fixture.logger.clone(),
    );
    restored.bootstrap(1_050).await.unwrap();
    assert_eq!(
        restored
            .recover_stalled_data_plane(
                &running.lease_id,
                StalledDataPlaneRecovery::RestartLocalTunnel,
            )
            .await
            .unwrap(),
        StalledDataPlaneRecoveryOutcome::Reconnected
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.tunnel.options.lock().unwrap().last(),
        Some(&TunnelOptions::default())
    );
}

#[tokio::test]
async fn owned_default_plan_save_does_not_reconstruct_a_stale_working_policy() {
    let (fixture, running) = fixture_with_owned_default_and_stale_working_policy().await;
    assert!(!fixture
        .core
        .split_tunnel_settings_require_reconnect(&same_split_settings())
        .await
        .unwrap());
    fixture
        .core
        .save_split_tunnel_settings(&same_split_settings(), 1_100)
        .await
        .unwrap();
    assert_eq!(
        fixture.tunnel.starts.load(Ordering::SeqCst),
        1,
        "a confirmed default plan is available, not a signal to reconstruct stale routes"
    );
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.tunnel.options.lock().unwrap().last(),
        Some(&TunnelOptions::default())
    );
    assert_eq!(fixture.core.state().await.connection, Some(running));
}

#[tokio::test]
async fn owned_default_plan_rollback_restores_the_actual_empty_recipe() {
    let (fixture, running) = fixture_with_owned_default_and_stale_working_policy().await;
    let mut enabled = policy(SplitTunnelMode::ExcludeSelected);
    enabled.policy_hash = format!("sha256:{}", "c".repeat(64));
    enabled.exclude_local_networks = false;
    fixture.api.set_policy(enabled);
    fixture.tunnel.fail_next_starts.store(1, Ordering::SeqCst);
    let request = SplitTunnelSettingsUpdate {
        mode: SplitTunnelMode::ExcludeSelected,
        exclude_local_networks: false,
        selected_packages: Vec::new(),
    };
    assert!(
        matches!(fixture.core.save_split_tunnel_settings(&request, 1_100).await,
        Err(CoreError::SplitTunnel(code)) if code == "split_tunnel_apply_failed")
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 3);
    assert_eq!(
        fixture.tunnel.options.lock().unwrap().last(),
        Some(&TunnelOptions::default()),
        "rollback must restore the dispatched default plan, not the old stored split policy"
    );
    assert_eq!(fixture.core.state().await.connection, Some(running));
    assert_eq!(
        fixture
            .api
            .apply_results
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .status,
        SplitTunnelApplyStatus::RolledBack
    );
}

async fn fixture_with_owned_default_and_stale_working_policy() -> (CoordinatorFixture, Connection) {
    let fixture = coordinator_fixture(android_35_capabilities());
    let old = policy(SplitTunnelMode::ExcludeSelected);
    let mut disabled = old.clone();
    disabled.enabled = false;
    disabled.policy_hash = format!("sha256:{}", "b".repeat(64));
    fixture.api.set_policy(disabled.clone());
    fixture
        .split_store
        .save(&StoredSplitTunnelState {
            cached_policy: Some(disabled),
            previous_working_policy: Some(old.clone()),
            working_policy_hash: Some(old.policy_hash.clone()),
            ..StoredSplitTunnelState::default()
        })
        .unwrap();
    let running = fixture
        .core
        .start(ConnectOptions::android_default(), 1_000)
        .await
        .unwrap();
    assert_eq!(
        fixture.tunnel.options.lock().unwrap().last(),
        Some(&TunnelOptions::default())
    );
    assert_eq!(
        fixture.split_store.load().unwrap().working_policy_hash,
        Some(old.policy_hash)
    );
    (fixture, running)
}

#[tokio::test]
async fn settings_confirmation_uses_live_plan_instead_of_changed_cache() {
    let fixture = coordinator_fixture(android_35_capabilities());
    fixture
        .core
        .synchronize_split_tunnel(900, false)
        .await
        .unwrap();
    let running = fixture
        .core
        .start(ConnectOptions::android_default(), 1_000)
        .await
        .unwrap();
    assert!(
        fixture
            .tunnel
            .options
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .exclude_local_networks
    );
    let mut cached_off = policy(SplitTunnelMode::ExcludeSelected);
    cached_off.exclude_local_networks = false;
    cached_off.policy_hash = format!("sha256:{}", "b".repeat(64));
    fixture
        .split_store
        .save(&StoredSplitTunnelState {
            cached_policy: Some(cached_off.clone()),
            working_policy_hash: Some(cached_off.policy_hash.clone()),
            ..StoredSplitTunnelState::default()
        })
        .unwrap();
    fixture.api.set_bootstrap_connection(running);
    fixture.core.bootstrap(1_050).await.unwrap();
    let request = SplitTunnelSettingsUpdate {
        mode: cached_off.mode,
        exclude_local_networks: false,
        selected_packages: Vec::new(),
    };
    assert!(fixture
        .core
        .split_tunnel_settings_require_reconnect(&request)
        .await
        .unwrap());
    fixture.api.set_policy(cached_off);
    fixture
        .core
        .save_split_tunnel_settings(&request, 1_100)
        .await
        .unwrap();
    assert!(
        !fixture
            .tunnel
            .options
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .exclude_local_networks
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
    fixture
        .core
        .save_split_tunnel_settings(&request, 1_200)
        .await
        .unwrap();
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn background_start_bootstrap_recovers_configuration_and_reapplies_policy() {
    for starting in [false, true] {
        let fixture =
            coordinator_fixture(capabilities(TunnelPlatform::Android, Some(35), true, true));
        fixture
            .core
            .set_split_tunnel_installed_packages(installed());
        let initial = policy(SplitTunnelMode::ExcludeSelected);
        let mut split_state = StoredSplitTunnelState {
            cached_policy: Some(initial.clone()),
            working_policy_hash: Some(initial.policy_hash.clone()),
            applied_physical_network_fingerprint: Some("network-a".into()),
            ..StoredSplitTunnelState::default()
        };
        fixture.split_store.save(&split_state).unwrap();
        let running = Connection {
            lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
            session_id: None,
            pool_id: None,
            layer: Layer::Tic,
            transport_protocol: Default::default(),
            tic_connection_mode: TicConnectionMode::Dynamic,
            route_mode: RouteMode::ViaTak,
            egress_mode: EgressMode::Ipv4,
            probe_url: Some("https://1a.example.test/probe".to_string()),
            status: LeaseStatus::Connected,
            pinned: false,
            stopped_at: None,
        };
        fixture.api.set_bootstrap_connection(running.clone());
        *fixture.tunnel.status.lock().unwrap() = if starting {
            TunnelStatus::Starting
        } else {
            TunnelStatus::Running
        };

        fixture.core.bootstrap(1_000).await.unwrap();
        if starting {
            assert_eq!(fixture.core.state().await.phase, Phase::Connecting);
            assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 0);
            *fixture.tunnel.status.lock().unwrap() = TunnelStatus::Running;
            assert_eq!(fixture.core.state().await.phase, Phase::Connected);
        }

        let recovered = fixture
            .secret_store
            .load()
            .unwrap()
            .unwrap()
            .saved_connection
            .expect("background connection configuration recovered");
        assert_eq!(recovered.lease_id, running.lease_id);
        assert_eq!(fixture.core.state().await.phase, Phase::Connected);
        assert_eq!(fixture.api.start_calls.load(Ordering::SeqCst), 1);

        fixture.tunnel.set_fingerprints(["network-a"]);
        assert_eq!(
            fixture.core.poll_physical_network(1_001).await.unwrap(),
            PhysicalNetworkPollOutcome::Unchanged
        );

        let mut changed = initial;
        changed.revision = 8;
        changed.force_revision = 3;
        changed.policy_hash = format!("sha256:{}", "b".repeat(64));
        changed.excluded_ipv4_cidrs = vec!["198.51.100.0/24".to_string()];
        fixture.api.set_policy(changed.clone());
        fixture
            .api
            .set_revision(changed.revision, changed.force_revision);

        assert_eq!(
            fixture
                .core
                .synchronize_split_tunnel(1_100, false)
                .await
                .unwrap(),
            SplitTunnelSyncOutcome::Updated { reconnected: true }
        );
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            *fixture.tunnel.status.lock().unwrap(),
            TunnelStatus::Running
        );
        assert_eq!(fixture.core.state().await.phase, Phase::Connected);
        assert_eq!(fixture.core.state().await.connection, Some(running));
        assert_eq!(fixture.core.split_tunnel_warning().await, None);
        split_state = fixture.split_store.load().unwrap();
        assert_eq!(
            split_state.working_policy_hash.as_deref(),
            Some(changed.policy_hash.as_str())
        );
    }
}

#[tokio::test]
async fn windows_without_policy_keeps_lan_and_defers_late_policy_until_next_start() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Windows, None, true, false));
    fixture.api.policy_online.store(false, Ordering::SeqCst);
    let options = ConnectOptions::windows_default();
    fixture.core.start(options.clone(), 1_000).await.unwrap();
    let started = fixture.tunnel.options.lock().unwrap()[0].clone();
    assert!(started.exclude_local_networks);
    assert!(started.excluded_ipv4_cidrs.is_empty());
    assert!(started.policy_hash.is_none());
    assert_eq!(fixture.api.policy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_local_only")
    );

    fixture.api.policy_online.store(true, Ordering::SeqCst);
    for now in [1_001, 1_301] {
        assert_eq!(
            fixture
                .core
                .synchronize_split_tunnel(now, false)
                .await
                .unwrap(),
            SplitTunnelSyncOutcome::Updated { reconnected: false }
        );
        assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.core.state().await.phase, Phase::Connected);
        assert_eq!(
            fixture.core.split_tunnel_warning().await.as_deref(),
            Some("split_tunnel_policy_deferred")
        );
        assert!(fixture
            .split_store
            .load()
            .unwrap()
            .working_policy_hash
            .is_none());
        assert!(fixture.api.apply_results.lock().unwrap().is_empty());
    }
    assert!(fixture.split_store.load().unwrap().cached_policy.is_some());
    fixture.api.stop_succeeds.store(true, Ordering::SeqCst);
    fixture.core.stop().await.unwrap();
    assert_eq!(fixture.core.split_tunnel_warning().await, None);
    fixture.core.start(options, 1_302).await.unwrap();
    let restarted = fixture.tunnel.options.lock().unwrap()[1].clone();
    assert!(restarted.exclude_local_networks);
    assert!(restarted.policy_hash.is_some());
    assert!(!restarted.excluded_ipv4_cidrs.is_empty());
    assert_eq!(fixture.core.split_tunnel_warning().await, None);
}

#[tokio::test]
async fn windows_deferred_warning_survives_runtime_status_failure_and_recovery() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Windows, None, true, false));
    fixture
        .core
        .start(ConnectOptions::windows_default(), 1_000)
        .await
        .unwrap();
    fixture
        .core
        .synchronize_split_tunnel(1_001, false)
        .await
        .unwrap();

    fixture
        .tunnel
        .fail_next_status
        .store(true, Ordering::SeqCst);
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("tunnel_status_unavailable")
    );
    assert_eq!(fixture.core.state().await.phase, Phase::Connected);
    assert_eq!(
        fixture.core.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_policy_deferred")
    );
    fixture.core.stop_locally().await.unwrap();
    assert_eq!(fixture.core.split_tunnel_warning().await, None);
}

#[tokio::test]
async fn windows_failed_start_does_not_claim_fallback_vpn_is_running() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Windows, None, true, false));
    fixture.tunnel.fail_next_starts.store(1, Ordering::SeqCst);
    assert!(fixture
        .core
        .start(ConnectOptions::windows_default(), 1_000)
        .await
        .is_err());
    assert_eq!(
        *fixture.tunnel.status.lock().unwrap(),
        TunnelStatus::Stopped
    );
    assert_eq!(fixture.core.split_tunnel_warning().await, None);
}

#[tokio::test]
async fn windows_cached_policy_starts_without_fetch_and_matching_late_routes_need_no_restart() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Windows, None, true, false));
    let mut local_only = policy(SplitTunnelMode::ExcludeSelected);
    local_only.excluded_ipv4_cidrs.clear();
    fixture.api.set_policy(local_only);
    fixture
        .core
        .start(ConnectOptions::windows_default(), 1_000)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_001, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: false }
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert!(fixture
        .split_store
        .load()
        .unwrap()
        .working_policy_hash
        .is_some());
    assert_eq!(fixture.core.split_tunnel_warning().await, None);

    fixture.api.stop_succeeds.store(true, Ordering::SeqCst);
    fixture.core.stop().await.unwrap();
    fixture.api.policy_online.store(false, Ordering::SeqCst);
    let fetches = fixture.api.policy_calls.load(Ordering::SeqCst);
    fixture
        .core
        .start(ConnectOptions::windows_default(), 1_002)
        .await
        .unwrap();
    assert_eq!(fixture.api.policy_calls.load(Ordering::SeqCst), fetches);
    assert!(fixture.tunnel.options.lock().unwrap()[1]
        .policy_hash
        .is_some());
}

#[tokio::test]
async fn windows_bootstrap_does_not_treat_downloaded_policy_as_already_applied() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Windows, None, true, false));
    fixture
        .core
        .start(ConnectOptions::windows_default(), 1_000)
        .await
        .unwrap();
    fixture
        .core
        .synchronize_split_tunnel(1_001, false)
        .await
        .unwrap();
    fixture
        .api
        .set_bootstrap_connection(fixture.core.state().await.connection.unwrap());
    let restored = support::core_with_split(
        fixture.api.clone(),
        fixture.secret_store.clone(),
        fixture.split_store.clone(),
        fixture.tunnel.clone(),
        fixture.logger.clone(),
    );
    restored.bootstrap(1_002).await.unwrap();
    assert_eq!(restored.state().await.phase, Phase::Connected);
    assert_eq!(
        restored.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_local_only")
    );
    restored
        .synchronize_split_tunnel(1_301, false)
        .await
        .unwrap();
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.tunnel.stops.load(Ordering::SeqCst), 0);
    assert!(fixture
        .split_store
        .load()
        .unwrap()
        .working_policy_hash
        .is_none());
    assert_eq!(restored.state().await.phase, Phase::Connected);
    assert_eq!(
        restored.split_tunnel_warning().await.as_deref(),
        Some("split_tunnel_policy_deferred")
    );
}

struct CoordinatorFixture {
    core: ClientCore<
        CoordinatorApi,
        support::LegacyRuntime<TestSecretStore>,
        CoordinatorTunnel,
        TestLogger,
    >,
    api: Arc<CoordinatorApi>,
    tunnel: Arc<CoordinatorTunnel>,
    split_store: Arc<MemorySplitTunnelStore>,
    logger: Arc<TestLogger>,
    secret_store: Arc<TestSecretStore>,
    local: Arc<nelomai_client_core::CoreLocalStop<CoordinatorTunnel>>,
}

fn coordinator_fixture(capabilities: TunnelCapabilities) -> CoordinatorFixture {
    let api = Arc::new(CoordinatorApi::new());
    let secret_store = Arc::new(TestSecretStore::new(StoredAuth {
        install_secret: "install".to_string(),
        access_token: Some("access".to_string()),
        refresh_token: Some("refresh".to_string()),
        saved_connection: None,
        pinned_connection: None,
        pending_start: None,
        pending_stalled_stop: None,
        pending_compensation_stop: None,
        compatibility: None,
    }));
    let tunnel = Arc::new(CoordinatorTunnel {
        capabilities,
        ..CoordinatorTunnel::default()
    });
    let split_store = Arc::new(MemorySplitTunnelStore::default());
    let logger = Arc::new(TestLogger::default());
    let local = nelomai_client_core::CoreLocalStop::new(tunnel.clone());
    let core = ClientCore::with_split_tunnel_store(
        api.clone(),
        Arc::new(support::LegacyRuntime::new(secret_store.clone())),
        split_store.clone(),
        Arc::new(support::TestOwner::new(
            api.clone(),
            secret_store.clone(),
            local.clone(),
        )),
        local.clone(),
        logger.clone(),
    );
    core.set_split_tunnel_installed_packages(installed());
    CoordinatorFixture {
        core,
        api,
        tunnel,
        split_store,
        logger,
        secret_store,
        local,
    }
}

fn android_35_capabilities() -> TunnelCapabilities {
    TunnelCapabilities {
        platform: TunnelPlatform::Android,
        android_api_level: Some(35),
        address_split_tunnel: true,
        application_split_tunnel: true,
    }
}

struct TestSecretStore {
    stored: Mutex<Option<StoredAuth>>,
    reject_compensation_journal_once: AtomicBool,
}

impl TestSecretStore {
    fn new(auth: StoredAuth) -> Self {
        Self {
            stored: Mutex::new(Some(auth)),
            reject_compensation_journal_once: AtomicBool::new(false),
        }
    }
}

impl SecretStore for TestSecretStore {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.stored.lock().unwrap().clone())
    }

    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError> {
        let introduces_compensation = self.stored.lock().unwrap().as_ref().is_some_and(|stored| {
            stored.pending_compensation_stop.is_none() && auth.pending_compensation_stop.is_some()
        });
        if introduces_compensation
            && self
                .reject_compensation_journal_once
                .swap(false, Ordering::SeqCst)
        {
            return Err(StorageError::SplitTunnelStateLock);
        }
        *self.stored.lock().unwrap() = Some(auth.clone());
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self.stored.lock().unwrap() = None;
        Ok(())
    }
}

#[derive(Default)]
struct FailingSplitTunnelStore {
    state: Mutex<StoredSplitTunnelState>,
    fail_saves: AtomicBool,
}

impl SplitTunnelStore for FailingSplitTunnelStore {
    fn load(&self) -> Result<StoredSplitTunnelState, StorageError> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| StorageError::SplitTunnelStateLock)
    }

    fn save(&self, state: &StoredSplitTunnelState) -> Result<(), StorageError> {
        if self.fail_saves.load(Ordering::SeqCst) {
            return Err(StorageError::SplitTunnelStateLock);
        }
        *self
            .state
            .lock()
            .map_err(|_| StorageError::SplitTunnelStateLock)? = state.clone();
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self
            .state
            .lock()
            .map_err(|_| StorageError::SplitTunnelStateLock)? = StoredSplitTunnelState::default();
        Ok(())
    }
}

#[derive(Default)]
struct TestLogger {
    events: Mutex<Vec<CoreLogEvent>>,
}

impl CoreLogger for TestLogger {
    fn record(&self, event: CoreLogEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[derive(Default)]
struct CoordinatorTunnel {
    capabilities: TunnelCapabilities,
    starts: AtomicUsize,
    stops: AtomicUsize,
    fail_next_starts: AtomicUsize,
    fail_next_stops: AtomicUsize,
    keep_running_on_stop_failure: AtomicBool,
    preserve_restart_intent: AtomicBool,
    independent_native_owner: AtomicBool,
    owned_session_scope: Mutex<Option<String>>,
    owned_policy_requests: Mutex<Vec<OwnedRedundantPolicyRequest>>,
    owned_policy_outcomes: Mutex<VecDeque<Result<OwnedRedundantPolicyOutcome, &'static str>>>,
    block_owned_policy: AtomicBool,
    owned_policy_entered: Notify,
    owned_policy_release: Notify,
    restart_starts: AtomicUsize,
    block_restart: AtomicBool,
    restart_release: Notify,
    options: Mutex<Vec<TunnelOptions>>,
    start_metadata: Mutex<Vec<(Option<QuickConnection>, QuickReconnect)>>,
    status: Mutex<TunnelStatus>,
    fail_next_status: AtomicBool,
    fingerprints: Mutex<VecDeque<String>>,
    fingerprint_calls: AtomicUsize,
    fail_next_fingerprint: AtomicBool,
    block_fingerprint: AtomicBool,
    fingerprint_release: Notify,
    capability_calls: AtomicUsize,
    block_capabilities: AtomicBool,
    capabilities_release: Notify,
    block_stop: AtomicBool,
    stop_release: Notify,
    operation_events: Mutex<Option<Arc<Mutex<Vec<&'static str>>>>>,
}

impl CoordinatorTunnel {
    fn set_fingerprints<'a>(&self, values: impl IntoIterator<Item = &'a str>) {
        *self.fingerprints.lock().unwrap() = values
            .into_iter()
            .map(str::to_string)
            .collect::<VecDeque<_>>();
    }
}

#[async_trait]
impl TunnelController for CoordinatorTunnel {
    async fn stop_if_unowned(&self) -> Result<(), TunnelError> {
        if self.independent_native_owner.load(Ordering::SeqCst) {
            return Err(TunnelError::Backend("runtime_v2_owned".into()));
        }
        self.stop().await
    }

    async fn owns_redundant_session(&self) -> Result<bool, TunnelError> {
        Ok(self.independent_native_owner.load(Ordering::SeqCst))
    }

    async fn apply_owned_redundant_policy(
        &self,
        request: OwnedRedundantPolicyRequest,
    ) -> Result<OwnedRedundantPolicyOutcome, TunnelError> {
        self.owned_policy_requests
            .lock()
            .unwrap()
            .push(request.clone());
        let outcome = self
            .owned_policy_outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(OwnedRedundantPolicyOutcome::Applied));
        match outcome {
            Ok(OwnedRedundantPolicyOutcome::Applied | OwnedRedundantPolicyOutcome::Unchanged) => {
                self.options.lock().unwrap().push(request.options);
            }
            Ok(OwnedRedundantPolicyOutcome::Failed) => {
                *self.status.lock().unwrap() = TunnelStatus::Stopped;
            }
            _ => {}
        }
        // Model a completed native operation whose IPC reply is delayed, not a
        // native implementation that restarts after cancellation without fencing.
        self.owned_policy_entered.notify_one();
        if self.block_owned_policy.load(Ordering::SeqCst) {
            self.owned_policy_release.notified().await;
        }
        outcome.map_err(|code| TunnelError::Backend(code.into()))
    }

    async fn start_for_restart(&self, request: TunnelStartRequest) -> Result<(), TunnelError> {
        self.restart_starts.fetch_add(1, Ordering::SeqCst);
        if self.block_restart.load(Ordering::SeqCst) {
            self.restart_release.notified().await;
        }
        self.start(request).await
    }

    async fn stop_for_restart(&self) -> Result<(), TunnelError> {
        if self.preserve_restart_intent.load(Ordering::SeqCst) {
            Ok(())
        } else {
            self.stop().await
        }
    }

    async fn start(&self, request: TunnelStartRequest) -> Result<(), TunnelError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        self.start_metadata
            .lock()
            .unwrap()
            .push((request.quick_connection.clone(), request.quick_reconnect));
        if self
            .fail_next_starts
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            *self.status.lock().unwrap() = TunnelStatus::Stopped;
            return Err(TunnelError::Backend("test_start_failed".to_string()));
        }
        self.options.lock().unwrap().push(request.options);
        *self.status.lock().unwrap() = TunnelStatus::Running;
        Ok(())
    }

    async fn stop(&self) -> Result<(), TunnelError> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        self.owned_session_scope.lock().unwrap().take();
        if let Some(events) = self.operation_events.lock().unwrap().clone() {
            events.lock().unwrap().push("local_stop");
        }
        if self.block_stop.load(Ordering::SeqCst) {
            self.stop_release.notified().await;
        }
        if self
            .fail_next_stops
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            if !self.keep_running_on_stop_failure.load(Ordering::SeqCst) {
                *self.status.lock().unwrap() = TunnelStatus::Stopped;
            }
            return Err(TunnelError::Backend("test_stop_failed".to_string()));
        }
        *self.status.lock().unwrap() = TunnelStatus::Stopped;
        Ok(())
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        if self.fail_next_status.swap(false, Ordering::SeqCst) {
            return Err(TunnelError::Backend("test_status_failed".to_string()));
        }
        Ok(*self.status.lock().unwrap())
    }

    async fn physical_network_fingerprint(&self) -> Result<Option<String>, TunnelError> {
        self.fingerprint_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_next_fingerprint.swap(false, Ordering::SeqCst) {
            return Err(TunnelError::Backend(
                "physical_egress_unavailable".to_string(),
            ));
        }
        if self.block_fingerprint.load(Ordering::SeqCst) {
            self.fingerprint_release.notified().await;
        }
        let mut fingerprints = self.fingerprints.lock().unwrap();
        let fingerprint = if fingerprints.len() > 1 {
            fingerprints.pop_front()
        } else {
            fingerprints.front().cloned()
        };
        Ok(fingerprint)
    }

    async fn capabilities(&self) -> Result<TunnelCapabilities, TunnelError> {
        self.capability_calls.fetch_add(1, Ordering::SeqCst);
        if self.block_capabilities.load(Ordering::SeqCst) {
            self.capabilities_release.notified().await;
        }
        Ok(self.capabilities)
    }
}

struct CoordinatorApi {
    online: AtomicBool,
    policy_online: AtomicBool,
    revision: Mutex<SplitTunnelRevision>,
    policy: Mutex<SplitTunnelPolicy>,
    revision_calls: AtomicUsize,
    policy_calls: AtomicUsize,
    start_calls: AtomicUsize,
    stop_calls: AtomicUsize,
    stop_succeeds: AtomicBool,
    stop_operation_ids: Mutex<Vec<String>>,
    operation_events: Mutex<Option<Arc<Mutex<Vec<&'static str>>>>>,
    settings_calls: AtomicUsize,
    apply_failures: AtomicUsize,
    apply_results: Mutex<Vec<SplitTunnelApplyResult>>,
    bootstrap_connection: Mutex<Option<Connection>>,
}

impl CoordinatorApi {
    fn new() -> Self {
        Self {
            online: AtomicBool::new(true),
            policy_online: AtomicBool::new(true),
            revision: Mutex::new(SplitTunnelRevision {
                enabled: true,
                revision: 7,
                force_revision: 2,
                address_revision: 0,
            }),
            policy: Mutex::new(policy(SplitTunnelMode::ExcludeSelected)),
            revision_calls: AtomicUsize::new(0),
            policy_calls: AtomicUsize::new(0),
            start_calls: AtomicUsize::new(0),
            stop_calls: AtomicUsize::new(0),
            stop_succeeds: AtomicBool::new(false),
            stop_operation_ids: Mutex::new(Vec::new()),
            operation_events: Mutex::new(None),
            settings_calls: AtomicUsize::new(0),
            apply_failures: AtomicUsize::new(0),
            apply_results: Mutex::new(Vec::new()),
            bootstrap_connection: Mutex::new(None),
        }
    }

    fn set_revision(&self, revision: i64, force_revision: i64) {
        *self.revision.lock().unwrap() = SplitTunnelRevision {
            enabled: true,
            revision,
            force_revision,
            address_revision: 0,
        };
    }

    fn set_policy(&self, policy: SplitTunnelPolicy) {
        *self.policy.lock().unwrap() = policy;
    }

    fn set_bootstrap_connection(&self, connection: Connection) {
        *self.bootstrap_connection.lock().unwrap() = Some(connection);
    }

    fn available(&self) -> Result<(), CoreApiError> {
        self.online
            .load(Ordering::SeqCst)
            .then_some(())
            .ok_or(CoreApiError::Retryable)
    }
}

#[async_trait]
impl CoreApi for CoordinatorApi {
    async fn bootstrap(&self, _access_token: &AccessSnapshot) -> Result<Bootstrap, CoreApiError> {
        self.available()?;
        let connection = self.bootstrap_connection.lock().unwrap().clone();
        Ok(Bootstrap {
            api_version: ApiVersion::V1,
            request_id: "bootstrap".to_string(),
            access: Access {
                state: AccessState::Active,
                can_login: true,
                can_connect: true,
                expires_at: None,
            },
            device: Device {
                id: "device-1".to_string(),
                name: "Android".to_string(),
                platform: Platform::Android,
            },
            binding: Some(PeerBinding {
                id: "binding-1".to_string(),
                peer_id: "peer-1".to_string(),
                interface_id: "interface-1".to_string(),
                interface_name: "Tic".to_string(),
                slot: 1,
                preferred_layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Dynamic,
                route_mode: RouteMode::ViaTak,
                egress_mode: EgressMode::Ipv4,
            }),
            connection,
            pinned_stray: None,
            defaults: BootstrapDefaults {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Dynamic,
                route_mode: RouteMode::ViaTak,
            },
            update: UpdateState {
                current_version: Some("0.1.22".to_string()),
                minimum_version: None,
                update_available: false,
                required: false,
                release_notes: None,
            },
            capabilities: None,
        })
    }

    async fn start_connection(
        &self,
        _access_token: &AccessSnapshot,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        self.available()?;
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ConnectionStartResponse {
            api_version: ApiVersion::V1,
            request_id: "start".to_string(),
            connection: Connection {
                lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
                session_id: None,
                pool_id: None,
                layer: request.layer,
                transport_protocol: Default::default(),
                tic_connection_mode: request.tic_connection_mode,
                route_mode: request.route_mode,
                egress_mode: request.egress_mode,
                probe_url: Some("https://1a.example.test/probe".to_string()),
                status: LeaseStatus::Connected,
                pinned: false,
                stopped_at: None,
            },
            configuration: "[Interface]\nPrivateKey = secret\n".to_string(),
            health_probe: None,
            reused: false,
            redundancy: None,
        })
    }

    async fn stop_connection(
        &self,
        _access_token: &AccessSnapshot,
        request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        self.stop_operation_ids
            .lock()
            .unwrap()
            .push(request.operation_id.clone());
        if let Some(events) = self.operation_events.lock().unwrap().clone() {
            events.lock().unwrap().push("panel_stop");
        }
        if !self.stop_succeeds.load(Ordering::SeqCst) {
            return Err(CoreApiError::Retryable);
        }
        Ok(ConnectionOperationResponse {
            stop_acceptance: None,
            api_version: ApiVersion::V1,
            request_id: "stop".to_string(),
            connection: Connection {
                lease_id: request.lease_id.clone(),
                session_id: None,
                pool_id: None,
                layer: Layer::Tic,
                transport_protocol: Default::default(),
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::ViaTak,
                egress_mode: EgressMode::Ipv4,
                probe_url: None,
                status: LeaseStatus::Released,
                pinned: false,
                stopped_at: Some("2026-08-30T10:00:00Z".to_string()),
            },
        })
    }

    async fn pin_stray(
        &self,
        _access_token: &AccessSnapshot,
        _request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }

    async fn unpin_stray(
        &self,
        _access_token: &AccessSnapshot,
        _request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }

    async fn split_tunnel_revision(
        &self,
        _access_token: &AccessSnapshot,
    ) -> Result<SplitTunnelRevision, CoreApiError> {
        self.available()?;
        self.revision_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.revision.lock().unwrap().clone())
    }

    async fn split_tunnel_policy(
        &self,
        _access_token: &AccessSnapshot,
    ) -> Result<SplitTunnelPolicy, CoreApiError> {
        self.available()?;
        if !self.policy_online.load(Ordering::SeqCst) {
            return Err(CoreApiError::Retryable);
        }
        self.policy_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.policy.lock().unwrap().clone())
    }

    async fn update_split_tunnel_settings(
        &self,
        _access_token: &AccessSnapshot,
        _request: &SplitTunnelSettingsUpdate,
    ) -> Result<SplitTunnelPolicy, CoreApiError> {
        self.available()?;
        self.settings_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.policy.lock().unwrap().clone())
    }

    async fn report_split_tunnel_apply_result(
        &self,
        _access_token: &AccessSnapshot,
        request: &SplitTunnelApplyResult,
    ) -> Result<(), CoreApiError> {
        self.available()?;
        if self
            .apply_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(CoreApiError::Retryable);
        }
        self.apply_results.lock().unwrap().push(request.clone());
        Ok(())
    }
}

#[async_trait]
impl support::TestAuthApi for CoordinatorApi {
    async fn refresh(&self, _refresh_token: &str) -> Result<TokenResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }
}
