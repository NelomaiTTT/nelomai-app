use async_trait::async_trait;
use nelomai_client_api::TokenResponse;
use nelomai_client_core::{
    split_tunnel_active, ClientCore, ConnectOptions, CoreApi, CoreApiError, CoreError,
    CoreLogEvent, CoreLogger, EffectiveSplitTunnelPolicy, Phase, PhysicalNetworkPollOutcome,
    SplitTunnelContext, SplitTunnelPolicyError, SplitTunnelSyncOutcome,
};
use nelomai_client_storage::{
    MemorySplitTunnelStore, SecretStore, SplitTunnelStore, StorageError, StoredAuth,
    StoredSplitTunnelState,
};
use nelomai_client_tunnel::{
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
    let core = ClientCore::with_split_tunnel_store(
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
    let reconstructed = ClientCore::with_split_tunnel_store(
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
        .set_fingerprints(["network-a", "network-b", "network-b"]);
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

    assert_eq!(
        fixture.core.poll_physical_network(1_100).await.unwrap(),
        PhysicalNetworkPollOutcome::ChangePending
    );
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 1);
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
async fn background_start_bootstrap_recovers_configuration_and_reapplies_policy() {
    let fixture = coordinator_fixture(capabilities(TunnelPlatform::Android, Some(35), true, true));
    fixture
        .core
        .set_split_tunnel_installed_packages(installed());
    let initial = policy(SplitTunnelMode::ExcludeSelected);
    let mut split_state = StoredSplitTunnelState {
        cached_policy: Some(initial.clone()),
        working_policy_hash: Some(initial.policy_hash.clone()),
        ..StoredSplitTunnelState::default()
    };
    fixture.split_store.save(&split_state).unwrap();
    let running = Connection {
        lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
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
    *fixture.tunnel.status.lock().unwrap() = TunnelStatus::Running;

    fixture.core.bootstrap(1_000).await.unwrap();

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

struct CoordinatorFixture {
    core: ClientCore<CoordinatorApi, TestSecretStore, CoordinatorTunnel, TestLogger>,
    api: Arc<CoordinatorApi>,
    tunnel: Arc<CoordinatorTunnel>,
    split_store: Arc<MemorySplitTunnelStore>,
    logger: Arc<TestLogger>,
    secret_store: Arc<TestSecretStore>,
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
    let core = ClientCore::with_split_tunnel_store(
        api.clone(),
        secret_store.clone(),
        split_store.clone(),
        tunnel.clone(),
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
    options: Mutex<Vec<TunnelOptions>>,
    status: Mutex<TunnelStatus>,
    fingerprints: Mutex<VecDeque<String>>,
    fingerprint_calls: AtomicUsize,
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
    async fn start(&self, request: TunnelStartRequest) -> Result<(), TunnelError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
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
        Ok(*self.status.lock().unwrap())
    }

    async fn physical_network_fingerprint(&self) -> Result<Option<String>, TunnelError> {
        self.fingerprint_calls.fetch_add(1, Ordering::SeqCst);
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
    async fn refresh(&self, _refresh_token: &str) -> Result<TokenResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }

    async fn bootstrap(&self, _access_token: &str) -> Result<Bootstrap, CoreApiError> {
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
        _access_token: &str,
        request: &ConnectionStartRequest,
    ) -> Result<ConnectionStartResponse, CoreApiError> {
        self.available()?;
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ConnectionStartResponse {
            api_version: ApiVersion::V1,
            request_id: "start".to_string(),
            connection: Connection {
                lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
                pool_id: None,
                layer: request.layer,
                transport_protocol: Default::default(),
                tic_connection_mode: request.tic_connection_mode,
                route_mode: request.route_mode,
                egress_mode: EgressMode::Ipv4,
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
        _access_token: &str,
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
            api_version: ApiVersion::V1,
            request_id: "stop".to_string(),
            connection: Connection {
                lease_id: request.lease_id.clone(),
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
        _access_token: &str,
        _request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }

    async fn unpin_stray(
        &self,
        _access_token: &str,
        _request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
    }

    async fn split_tunnel_revision(
        &self,
        _access_token: &str,
    ) -> Result<SplitTunnelRevision, CoreApiError> {
        self.available()?;
        self.revision_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.revision.lock().unwrap().clone())
    }

    async fn split_tunnel_policy(
        &self,
        _access_token: &str,
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
        _access_token: &str,
        _request: &SplitTunnelSettingsUpdate,
    ) -> Result<SplitTunnelPolicy, CoreApiError> {
        self.available()?;
        self.settings_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.policy.lock().unwrap().clone())
    }

    async fn report_split_tunnel_apply_result(
        &self,
        _access_token: &str,
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
