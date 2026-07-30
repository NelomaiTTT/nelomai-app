use nelomai_client_core::{
    split_tunnel_active, EffectiveSplitTunnelPolicy, SplitTunnelContext, SplitTunnelPolicyError,
};
use nelomai_client_tunnel::{TunnelCapabilities, TunnelOptions, TunnelPlatform};
use nelomai_contracts::{
    Layer, RouteMode, SplitTunnelMode, SplitTunnelPolicy, SplitTunnelSelectedPackage,
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
