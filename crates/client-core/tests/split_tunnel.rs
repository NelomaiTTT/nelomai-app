use async_trait::async_trait;
use nelomai_client_api::TokenResponse;
use nelomai_client_core::{
    split_tunnel_active, ClientCore, ConnectOptions, CoreApi, CoreApiError, CoreError,
    CoreLogEvent, CoreLogger, EffectiveSplitTunnelPolicy, Phase, SplitTunnelContext,
    SplitTunnelPolicyError, SplitTunnelSyncOutcome,
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
    ApiVersion, Bootstrap, Connection, ConnectionOperationRequest, ConnectionOperationResponse,
    ConnectionStartRequest, ConnectionStartResponse, Layer, LeaseStatus, RouteMode,
    SplitTunnelApplyResult, SplitTunnelApplyStatus, SplitTunnelMode, SplitTunnelPolicy,
    SplitTunnelRevision, SplitTunnelSelectedPackage, SplitTunnelSettingsUpdate, TicConnectionMode,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

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
            false,
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
            false,
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
fn android_33_uses_split_for_via_tak_and_stray_but_not_standalone_tic() {
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
    assert_eq!(standalone.options, TunnelOptions::default());
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

    for (api, layer, route_mode) in [
        (Some(32), Layer::Tic, RouteMode::ViaTak),
        (Some(35), Layer::Tic, RouteMode::Standalone),
    ] {
        let inactive = EffectiveSplitTunnelPolicy::build(
            &policy,
            &[],
            capabilities(TunnelPlatform::Android, api, true, true),
            layer,
            route_mode,
        )
        .unwrap();
        assert_eq!(inactive.options, TunnelOptions::default());
    }
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
        policy_hash: format!("sha256:{}", "a".repeat(64)),
        mode,
        exclude_local_networks: true,
        mandatory_excluded_packages: Vec::new(),
        suggested_name_fragments: Vec::new(),
        selected_packages: Vec::new(),
        excluded_ipv4_cidrs: vec!["203.0.113.0/24".to_string()],
        generated_at: "2026-07-30T12:00:00Z".to_string(),
    }
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

    fixture.api.online.store(false, Ordering::SeqCst);
    assert_eq!(
        fixture
            .core
            .synchronize_split_tunnel(1_600, false)
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

    assert!(matches!(
        fixture
            .core
            .synchronize_split_tunnel(1_900, false)
            .await
            .unwrap(),
        SplitTunnelSyncOutcome::Updated { reconnected: true }
    ));
    assert_eq!(fixture.tunnel.starts.load(Ordering::SeqCst), 4);
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
    assert_eq!(fixture.core.state().await.phase, Phase::Ready);
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
        (2, "split_tunnel_rollback_failed", Phase::Ready),
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
    let secret_store = Arc::new(TestSecretStore(Mutex::new(Some(StoredAuth {
        install_secret: "install".to_string(),
        access_token: Some("access".to_string()),
        refresh_token: Some("refresh".to_string()),
        saved_connection: None,
        pinned_connection: None,
        compatibility: None,
    }))));
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
async fn inactive_split_modes_sync_without_reconnect() {
    for (capabilities, options) in [
        (
            android_35_capabilities(),
            ConnectOptions {
                layer: Layer::Tic,
                tic_connection_mode: TicConnectionMode::Personal,
                route_mode: RouteMode::Standalone,
                probes: Vec::new(),
                allow_alternate: true,
            },
        ),
        (
            TunnelCapabilities {
                platform: TunnelPlatform::Android,
                android_api_level: Some(32),
                address_split_tunnel: false,
                application_split_tunnel: false,
            },
            ConnectOptions::android_default(),
        ),
    ] {
        let fixture = coordinator_fixture(capabilities);
        fixture
            .core
            .synchronize_split_tunnel(1_000, false)
            .await
            .unwrap();
        fixture.core.start(options, 1_010).await.unwrap();
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
                probes: Vec::new(),
                allow_alternate: true,
            },
            1_010,
        )
        .await
        .unwrap();
    assert!(!standalone
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
    unsupported.format_version = 2;
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
}

#[tokio::test]
async fn failed_apply_result_is_queued_and_retried_on_the_next_authenticated_sync() {
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

struct CoordinatorFixture {
    core: ClientCore<CoordinatorApi, TestSecretStore, CoordinatorTunnel, TestLogger>,
    api: Arc<CoordinatorApi>,
    tunnel: Arc<CoordinatorTunnel>,
    split_store: Arc<MemorySplitTunnelStore>,
    logger: Arc<TestLogger>,
}

fn coordinator_fixture(capabilities: TunnelCapabilities) -> CoordinatorFixture {
    let api = Arc::new(CoordinatorApi::new());
    let secret_store = Arc::new(TestSecretStore(Mutex::new(Some(StoredAuth {
        install_secret: "install".to_string(),
        access_token: Some("access".to_string()),
        refresh_token: Some("refresh".to_string()),
        saved_connection: None,
        pinned_connection: None,
        compatibility: None,
    }))));
    let tunnel = Arc::new(CoordinatorTunnel {
        capabilities,
        ..CoordinatorTunnel::default()
    });
    let split_store = Arc::new(MemorySplitTunnelStore::default());
    let logger = Arc::new(TestLogger::default());
    let core = ClientCore::with_split_tunnel_store(
        api.clone(),
        secret_store,
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

struct TestSecretStore(Mutex<Option<StoredAuth>>);

impl SecretStore for TestSecretStore {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(auth.clone());
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
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
    options: Mutex<Vec<TunnelOptions>>,
    status: Mutex<TunnelStatus>,
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
        *self.status.lock().unwrap() = TunnelStatus::Stopped;
        Ok(())
    }

    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(*self.status.lock().unwrap())
    }

    async fn capabilities(&self) -> Result<TunnelCapabilities, TunnelError> {
        Ok(self.capabilities)
    }
}

struct CoordinatorApi {
    online: AtomicBool,
    revision: Mutex<SplitTunnelRevision>,
    policy: Mutex<SplitTunnelPolicy>,
    revision_calls: AtomicUsize,
    policy_calls: AtomicUsize,
    start_calls: AtomicUsize,
    settings_calls: AtomicUsize,
    apply_failures: AtomicUsize,
    apply_results: Mutex<Vec<SplitTunnelApplyResult>>,
}

impl CoordinatorApi {
    fn new() -> Self {
        Self {
            online: AtomicBool::new(true),
            revision: Mutex::new(SplitTunnelRevision {
                enabled: true,
                revision: 7,
                force_revision: 2,
            }),
            policy: Mutex::new(policy(SplitTunnelMode::ExcludeSelected)),
            revision_calls: AtomicUsize::new(0),
            policy_calls: AtomicUsize::new(0),
            start_calls: AtomicUsize::new(0),
            settings_calls: AtomicUsize::new(0),
            apply_failures: AtomicUsize::new(0),
            apply_results: Mutex::new(Vec::new()),
        }
    }

    fn set_revision(&self, revision: i64, force_revision: i64) {
        *self.revision.lock().unwrap() = SplitTunnelRevision {
            enabled: true,
            revision,
            force_revision,
        };
    }

    fn set_policy(&self, policy: SplitTunnelPolicy) {
        *self.policy.lock().unwrap() = policy;
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
        Err(CoreApiError::Retryable)
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
                layer: request.layer,
                tic_connection_mode: request.tic_connection_mode,
                route_mode: request.route_mode,
                status: LeaseStatus::Connected,
                pinned: false,
                stopped_at: None,
            },
            configuration: "[Interface]\nPrivateKey = secret\n".to_string(),
            reused: false,
        })
    }

    async fn stop_connection(
        &self,
        _access_token: &str,
        _request: &ConnectionOperationRequest,
    ) -> Result<ConnectionOperationResponse, CoreApiError> {
        Err(CoreApiError::Retryable)
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
