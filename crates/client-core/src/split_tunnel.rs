use nelomai_client_tunnel::{TunnelCapabilities, TunnelOptions, TunnelPlatform};
use nelomai_contracts::{
    Layer, RouteMode, SplitTunnelMode, SplitTunnelPolicy, SplitTunnelSelectedPackage,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
};
use thiserror::Error;

const SUPPORTED_FORMAT_VERSION: u16 = 1;
const MAX_MANDATORY_PACKAGES: usize = 512;
const MAX_SUGGESTIONS: usize = 128;
const MAX_SELECTED_PACKAGES: usize = 512;
const MAX_IPV4_CIDRS: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitTunnelContext {
    pub global_enabled: bool,
    pub platform: TunnelPlatform,
    pub android_api_level: Option<u32>,
    pub layer: Layer,
    pub route_mode: RouteMode,
}

pub fn split_tunnel_active(context: SplitTunnelContext) -> bool {
    if !context.global_enabled {
        return false;
    }
    if context.platform == TunnelPlatform::Android
        && context.android_api_level.is_some_and(|level| level <= 32)
    {
        return false;
    }
    match (context.layer, context.route_mode) {
        (Layer::Tic, RouteMode::ViaTak) => true,
        (Layer::Tic, RouteMode::Standalone) => false,
        (Layer::Stray, _) => true,
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EffectiveSplitTunnelPolicy {
    pub active: bool,
    pub options: TunnelOptions,
    pub suggested_packages: Vec<SplitTunnelSelectedPackage>,
    pub unavailable_selected_packages: Vec<String>,
}

impl fmt::Debug for EffectiveSplitTunnelPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectiveSplitTunnelPolicy")
            .field("active", &self.active)
            .field("options", &self.options)
            .field("suggested_packages_count", &self.suggested_packages.len())
            .field(
                "unavailable_selected_packages_count",
                &self.unavailable_selected_packages.len(),
            )
            .finish()
    }
}

impl EffectiveSplitTunnelPolicy {
    pub fn build(
        policy: &SplitTunnelPolicy,
        installed_packages: &[SplitTunnelSelectedPackage],
        capabilities: TunnelCapabilities,
        layer: Layer,
        route_mode: RouteMode,
    ) -> Result<Self, SplitTunnelPolicyError> {
        validate_policy(policy)?;
        let active = split_tunnel_active(SplitTunnelContext {
            global_enabled: policy.enabled,
            platform: capabilities.platform,
            android_api_level: capabilities.android_api_level,
            layer,
            route_mode,
        });
        if !active {
            return Ok(Self {
                active: false,
                options: TunnelOptions::default(),
                suggested_packages: Vec::new(),
                unavailable_selected_packages: Vec::new(),
            });
        }

        let installed_by_id = installed_packages
            .iter()
            .map(|package| (package.package_id.as_str(), package))
            .collect::<HashMap<_, _>>();
        let mandatory = policy
            .mandatory_excluded_packages
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let selected = policy
            .selected_packages
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();

        let unavailable_selected_packages = policy
            .selected_packages
            .iter()
            .filter(|package_id| !installed_by_id.contains_key(package_id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let suggested_packages = suggested_packages(
            installed_packages,
            &policy.suggested_name_fragments,
            &mandatory,
            &selected,
        );

        let (application_mode, package_ids) = if capabilities.application_split_tunnel {
            let package_ids = match policy.mode {
                SplitTunnelMode::ExcludeSelected => ordered_available_packages(
                    policy
                        .mandatory_excluded_packages
                        .iter()
                        .chain(policy.selected_packages.iter()),
                    &installed_by_id,
                    &HashSet::new(),
                ),
                SplitTunnelMode::IncludeSelected => ordered_available_packages(
                    policy.selected_packages.iter(),
                    &installed_by_id,
                    &mandatory,
                ),
            };
            if policy.mode == SplitTunnelMode::IncludeSelected && package_ids.is_empty() {
                return Err(SplitTunnelPolicyError::EmptyIncludeSelection);
            }
            (Some(policy.mode), package_ids)
        } else {
            (None, Vec::new())
        };

        let options = TunnelOptions {
            application_mode,
            package_ids,
            excluded_ipv4_cidrs: if capabilities.address_split_tunnel {
                policy.excluded_ipv4_cidrs.clone()
            } else {
                Vec::new()
            },
            exclude_local_networks: capabilities.address_split_tunnel
                && policy.exclude_local_networks,
            policy_hash: Some(policy.policy_hash.clone()),
        };
        options
            .validate()
            .map_err(|error| SplitTunnelPolicyError::InvalidTunnelOptions {
                code: error.stable_code(),
            })?;

        Ok(Self {
            active: true,
            options,
            suggested_packages,
            unavailable_selected_packages,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SplitTunnelPolicyError {
    #[error("unsupported split-tunnel policy format")]
    UnsupportedFormat,
    #[error("split-tunnel policy timestamp is invalid")]
    InvalidTimestamp,
    #[error("split-tunnel mandatory package limit exceeded")]
    MandatoryPackagesLimit,
    #[error("split-tunnel suggestion limit exceeded")]
    SuggestionsLimit,
    #[error("split-tunnel selected package limit exceeded")]
    SelectedPackagesLimit,
    #[error("split-tunnel CIDR limit exceeded")]
    CidrsLimit,
    #[error("include-only split-tunnel requires at least one available application")]
    EmptyIncludeSelection,
    #[error("split-tunnel options are invalid: {code}")]
    InvalidTunnelOptions { code: &'static str },
}

impl SplitTunnelPolicyError {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::UnsupportedFormat => "split_tunnel_unsupported_format",
            Self::InvalidTimestamp => "split_tunnel_invalid_timestamp",
            Self::MandatoryPackagesLimit => "split_tunnel_mandatory_packages_limit",
            Self::SuggestionsLimit => "split_tunnel_suggestions_limit",
            Self::SelectedPackagesLimit => "split_tunnel_selected_packages_limit",
            Self::CidrsLimit => "split_tunnel_cidrs_limit",
            Self::EmptyIncludeSelection => "split_tunnel_empty_include_selection",
            Self::InvalidTunnelOptions { code } => code,
        }
    }
}

fn validate_policy(policy: &SplitTunnelPolicy) -> Result<(), SplitTunnelPolicyError> {
    if policy.format_version != SUPPORTED_FORMAT_VERSION {
        return Err(SplitTunnelPolicyError::UnsupportedFormat);
    }
    policy
        .validate_timestamps()
        .map_err(|_| SplitTunnelPolicyError::InvalidTimestamp)?;
    if policy.mandatory_excluded_packages.len() > MAX_MANDATORY_PACKAGES {
        return Err(SplitTunnelPolicyError::MandatoryPackagesLimit);
    }
    if policy.suggested_name_fragments.len() > MAX_SUGGESTIONS {
        return Err(SplitTunnelPolicyError::SuggestionsLimit);
    }
    if policy.selected_packages.len() > MAX_SELECTED_PACKAGES {
        return Err(SplitTunnelPolicyError::SelectedPackagesLimit);
    }
    if policy.excluded_ipv4_cidrs.len() > MAX_IPV4_CIDRS {
        return Err(SplitTunnelPolicyError::CidrsLimit);
    }
    Ok(())
}

fn ordered_available_packages<'a>(
    package_ids: impl Iterator<Item = &'a String>,
    installed_by_id: &HashMap<&str, &SplitTunnelSelectedPackage>,
    excluded: &HashSet<&str>,
) -> Vec<String> {
    let mut seen = HashSet::new();
    package_ids
        .filter(|package_id| installed_by_id.contains_key(package_id.as_str()))
        .filter(|package_id| !excluded.contains(package_id.as_str()))
        .filter(|package_id| seen.insert(package_id.as_str()))
        .cloned()
        .collect()
}

fn suggested_packages(
    installed_packages: &[SplitTunnelSelectedPackage],
    fragments: &[String],
    mandatory: &HashSet<&str>,
    selected: &HashSet<&str>,
) -> Vec<SplitTunnelSelectedPackage> {
    let fragments = fragments
        .iter()
        .map(|fragment| fragment.to_lowercase())
        .collect::<Vec<_>>();
    installed_packages
        .iter()
        .filter(|package| !mandatory.contains(package.package_id.as_str()))
        .filter(|package| !selected.contains(package.package_id.as_str()))
        .filter(|package| {
            let display_name = package.display_name.to_lowercase();
            fragments
                .iter()
                .any(|fragment| display_name.contains(fragment))
        })
        .cloned()
        .collect()
}
