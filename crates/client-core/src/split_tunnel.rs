use crate::{
    ClientCore, CoreApi, CoreApiError, CoreError, CoreLogger, Phase, SplitTunnelWarningKind,
};
use futures::{stream, StreamExt};
use nelomai_client_api::AccessSnapshot;
use nelomai_client_storage::{
    RuntimeStateStore, StoredSplitTunnelDomainResolution, StoredSplitTunnelState,
};
use nelomai_client_tunnel::{
    DesktopTunnelOptions, OwnedRedundantPolicyOutcome, OwnedRedundantPolicyRequest,
    QuickConnection, TunnelCapabilities, TunnelOptions, TunnelPlatform,
};
use nelomai_contracts::{
    Connection, Layer, RouteMode, SplitTunnelAddressRuleKind, SplitTunnelAddressRuleScope,
    SplitTunnelAddressRuleUpdate, SplitTunnelApplyResult, SplitTunnelApplyStatus, SplitTunnelMode,
    SplitTunnelPolicy, SplitTunnelRevision, SplitTunnelSelectedPackage, SplitTunnelSettingsUpdate,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    net::IpAddr,
    time::Duration,
};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::Url;

const LEGACY_FORMAT_VERSION: u16 = 1;
const ADDRESS_RULE_FORMAT_VERSION: u16 = 2;
const MAX_MANDATORY_PACKAGES: usize = 512;
const MAX_SUGGESTIONS: usize = 128;
const MAX_SELECTED_PACKAGES: usize = 512;
const MAX_IPV4_CIDRS: usize = 16_384;
const MAX_ADDRESS_RULES: usize = 512;
const MAX_IPV4_ADDRESSES_PER_DOMAIN: usize = 64;
const DNS_CONCURRENCY: usize = 8;
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_BATCH_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_ADDRESS_RULE_INPUT_LENGTH: usize = 2_048;
const REVISION_POLL_SECONDS: i64 = 5 * 60;
const FULL_SYNC_SECONDS: i64 = 24 * 60 * 60;
const FAILED_POLICY_RETRY_SECONDS: i64 = 60 * 60;
const PHYSICAL_NETWORK_RETRY_SECONDS: i64 = 5 * 60;
const UNKNOWN_PHYSICAL_NETWORK: &str = "restore_requires_network_revalidation";

#[derive(Clone, Default)]
pub(crate) struct RunningSplitTunnelOptions {
    pub(crate) options: TunnelOptions,
    // A usable restart recipe is distinct from proof of native application.
    // Default has neither; even a genuine empty plan must have an owner.
    available_to: Option<(String, crate::StartCancellationEpoch)>,
    native_confirmed: bool,
}

impl RunningSplitTunnelOptions {
    pub(crate) fn confirmed(
        options: TunnelOptions,
        lease_id: &str,
        epoch: crate::StartCancellationEpoch,
    ) -> Self {
        Self {
            options,
            available_to: Some((lease_id.to_owned(), epoch)),
            native_confirmed: true,
        }
    }

    fn is_available_for(&self, lease_id: &str, epoch: crate::StartCancellationEpoch) -> bool {
        self.available_to
            .as_ref()
            .is_some_and(|(owner, applied_epoch)| owner == lease_id && *applied_epoch == epoch)
    }

    fn is_confirmed_for(&self, lease_id: &str, epoch: crate::StartCancellationEpoch) -> bool {
        self.native_confirmed && self.is_available_for(lease_id, epoch)
    }
}

// Local restarts keep the accepted connection context (including Android's
// DNS46 mode), but neither cache a quick action nor select another lease.
fn local_restart_connection(connection: &Connection) -> QuickConnection {
    QuickConnection {
        lease_id: connection.lease_id.clone(),
        layer: connection.layer,
        tic_connection_mode: connection.tic_connection_mode,
        route_mode: connection.route_mode,
        egress_mode: connection.egress_mode,
        allow_alternate: false,
    }
}

fn same_local_recovery_execution(current: &Connection, expected: &Connection) -> bool {
    // Preserve the original exact-match behavior, including a locally running
    // offline/WARM execution. Do not turn Warm into an allowed transition.
    if current == expected {
        return true;
    }
    // Issued/Connected and probe URL are observations, not native ownership.
    // Retired lifecycle transitions and changed execution parameters still fence
    // the recovery, even if the cancellation epoch has not changed yet.
    matches!(
        current.status,
        nelomai_contracts::LeaseStatus::Issued | nelomai_contracts::LeaseStatus::Connected
    ) && matches!(
        expected.status,
        nelomai_contracts::LeaseStatus::Issued | nelomai_contracts::LeaseStatus::Connected
    ) && current.lease_id == expected.lease_id
        && current.session_id == expected.session_id
        && current.pool_id == expected.pool_id
        && current.layer == expected.layer
        && current.transport_protocol == expected.transport_protocol
        && current.tic_connection_mode == expected.tic_connection_mode
        && current.route_mode == expected.route_mode
        && current.egress_mode == expected.egress_mode
        && current.pinned == expected.pinned
        && current.stopped_at == expected.stopped_at
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalNetworkPollOutcome {
    Skipped,
    Busy,
    BaselineRecorded,
    ChangePending,
    RetryDeferred,
    Unchanged,
    Reconnected,
    ProbeFailed,
    ReconnectFailed,
}

#[derive(Debug, Default)]
pub(crate) struct PhysicalNetworkChangeDetector {
    applied: Option<String>,
    candidate: Option<String>,
    retry_after_unix: Option<i64>,
    probe_failed: bool,
    reconnect_after_probe_failure: bool,
    reconnect_failure_reported: bool,
}

impl PhysicalNetworkChangeDetector {
    fn observe(&mut self, fingerprint: String, now_unix: i64) -> PhysicalNetworkObservation {
        let reconnect_after_probe_failure = self.reconnect_after_probe_failure;
        self.probe_failed = false;
        self.reconnect_after_probe_failure = false;
        let Some(applied) = self.applied.as_deref() else {
            self.applied = Some(fingerprint);
            self.candidate = None;
            self.retry_after_unix = None;
            return PhysicalNetworkObservation::BaselineRecorded;
        };
        if self.candidate.as_deref() == Some(fingerprint.as_str()) {
            if self
                .retry_after_unix
                .is_some_and(|retry_after| now_unix < retry_after)
            {
                return PhysicalNetworkObservation::RetryDeferred;
            }
            self.retry_after_unix = None;
            return PhysicalNetworkObservation::ConfirmedChange(fingerprint);
        }
        if applied == fingerprint {
            if reconnect_after_probe_failure {
                self.candidate = Some(fingerprint.clone());
                self.retry_after_unix = None;
                self.reconnect_failure_reported = false;
                return PhysicalNetworkObservation::ConfirmedChange(fingerprint);
            }
            self.candidate = None;
            self.retry_after_unix = None;
            self.reconnect_failure_reported = false;
            return PhysicalNetworkObservation::Unchanged;
        }
        self.candidate = Some(fingerprint);
        self.retry_after_unix = None;
        self.reconnect_failure_reported = false;
        PhysicalNetworkObservation::ChangePending
    }

    fn defer_retry(&mut self, now_unix: i64) -> bool {
        self.retry_after_unix = Some(now_unix.saturating_add(PHYSICAL_NETWORK_RETRY_SECONDS));
        let should_report = !self.reconnect_failure_reported;
        self.reconnect_failure_reported = true;
        should_report
    }

    fn mark_applied(&mut self, fingerprint: String) {
        self.applied = Some(fingerprint);
        self.candidate = None;
        self.retry_after_unix = None;
        self.probe_failed = false;
        self.reconnect_after_probe_failure = false;
        self.reconnect_failure_reported = false;
    }

    fn require_revalidation(&mut self) {
        self.applied = Some(UNKNOWN_PHYSICAL_NETWORK.to_string());
        self.candidate = None;
        self.retry_after_unix = None;
        self.probe_failed = false;
        self.reconnect_after_probe_failure = false;
        self.reconnect_failure_reported = false;
    }

    fn mark_probe_failed(&mut self, reconnect_after_recovery: bool) -> bool {
        let first_failure = !self.probe_failed;
        self.probe_failed = true;
        self.reconnect_after_probe_failure |= reconnect_after_recovery;
        first_failure
    }

    pub(crate) fn reset(&mut self) {
        self.applied = None;
        self.candidate = None;
        self.retry_after_unix = None;
        self.probe_failed = false;
        self.reconnect_after_probe_failure = false;
        self.reconnect_failure_reported = false;
    }
}

fn probe_failure_requires_reconnect(error: &nelomai_client_tunnel::TunnelError) -> bool {
    matches!(
        error,
        nelomai_client_tunnel::TunnelError::Backend(code)
            if code == "physical_egress_unavailable"
    )
}

#[derive(Debug, PartialEq, Eq)]
enum PhysicalNetworkObservation {
    BaselineRecorded,
    ChangePending,
    RetryDeferred,
    Unchanged,
    ConfirmedChange(String),
}

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
        (Layer::Tic, RouteMode::ViaTak | RouteMode::Standalone) => true,
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
        Self::build_with_resolved_domains(
            policy,
            installed_packages,
            capabilities,
            layer,
            route_mode,
            &[],
        )
    }

    fn build_with_resolved_domains(
        policy: &SplitTunnelPolicy,
        installed_packages: &[SplitTunnelSelectedPackage],
        capabilities: TunnelCapabilities,
        layer: Layer,
        route_mode: RouteMode,
        resolved_domain_cidrs: &[String],
    ) -> Result<Self, SplitTunnelPolicyError> {
        validate_split_tunnel_policy(policy)?;
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

        let installed_index = InstalledPackageIndex::new(installed_packages);
        let installed_by_id = installed_packages
            .iter()
            .map(|package| (package.package_id.as_str(), package))
            .collect::<HashMap<_, _>>();
        let canonical_mandatory =
            canonical_available_packages(&policy.mandatory_excluded_packages, &installed_index);
        let canonical_selected =
            canonical_available_packages(&policy.selected_packages, &installed_index);
        let mandatory = canonical_mandatory
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        let selected = canonical_selected
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();

        let unavailable_selected_packages = policy
            .selected_packages
            .iter()
            .filter(|package_id| installed_index.resolve(package_id).is_none())
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
                    canonical_mandatory.iter().chain(canonical_selected.iter()),
                    &installed_by_id,
                    &HashSet::new(),
                ),
                SplitTunnelMode::IncludeSelected => ordered_available_packages(
                    canonical_selected.iter(),
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

        let mut excluded_ipv4_cidrs = policy.excluded_ipv4_cidrs.clone();
        if capabilities.address_split_tunnel {
            excluded_ipv4_cidrs.extend(policy.address_rules.iter().filter_map(|rule| {
                (rule.kind == SplitTunnelAddressRuleKind::Ipv4)
                    .then(|| rule.value.parse::<std::net::Ipv4Addr>().ok())
                    .flatten()
                    .map(|address| format!("{address}/32"))
            }));
            excluded_ipv4_cidrs.extend(resolved_domain_cidrs.iter().cloned());
            excluded_ipv4_cidrs.sort();
            excluded_ipv4_cidrs.dedup();
        } else {
            excluded_ipv4_cidrs.clear();
        }
        if excluded_ipv4_cidrs.len() > MAX_IPV4_CIDRS {
            return Err(SplitTunnelPolicyError::CidrsLimit);
        }

        let options = TunnelOptions {
            application_mode,
            package_ids,
            excluded_ipv4_cidrs,
            exclude_local_networks: capabilities.address_split_tunnel
                && (policy.exclude_local_networks
                    || matches!(
                        capabilities.platform,
                        TunnelPlatform::Windows | TunnelPlatform::Linux | TunnelPlatform::Macos
                    )),
            policy_hash: Some(policy.policy_hash.clone()),
            dns_servers: Vec::new(),
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
    #[error("split-tunnel address rule limit exceeded")]
    AddressRulesLimit,
    #[error("split-tunnel address rule is invalid")]
    InvalidAddressRule,
    #[error("split-tunnel address rules require policy format 2")]
    AddressRulesRequireFormatTwo,
    #[error("split-tunnel domain resolution is unavailable")]
    DomainResolutionUnavailable,
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
            Self::AddressRulesLimit => "split_tunnel_address_rules_limit",
            Self::InvalidAddressRule => "split_tunnel_address_rule_invalid",
            Self::AddressRulesRequireFormatTwo => "split_tunnel_address_rules_unsupported_format",
            Self::DomainResolutionUnavailable => "split_tunnel_domain_resolution_unavailable",
        }
    }
}

pub fn validate_split_tunnel_policy(
    policy: &SplitTunnelPolicy,
) -> Result<(), SplitTunnelPolicyError> {
    if !matches!(
        policy.format_version,
        LEGACY_FORMAT_VERSION | ADDRESS_RULE_FORMAT_VERSION
    ) {
        return Err(SplitTunnelPolicyError::UnsupportedFormat);
    }
    if policy.format_version == LEGACY_FORMAT_VERSION && !policy.address_rules.is_empty() {
        return Err(SplitTunnelPolicyError::AddressRulesRequireFormatTwo);
    }
    if policy.address_revision < 0 || policy.address_rules.len() > MAX_ADDRESS_RULES {
        return Err(SplitTunnelPolicyError::AddressRulesLimit);
    }
    for rule in &policy.address_rules {
        let valid = rule.id > 0
            && match rule.kind {
                SplitTunnelAddressRuleKind::Ipv4 => {
                    rule.value.parse::<std::net::Ipv4Addr>().is_ok()
                }
                SplitTunnelAddressRuleKind::Domain => valid_normalized_domain(&rule.value),
            };
        if !valid {
            return Err(SplitTunnelPolicyError::InvalidAddressRule);
        }
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
    let validate_packages = |mode, package_ids: &[String]| {
        TunnelOptions {
            application_mode: Some(mode),
            package_ids: package_ids.to_vec(),
            policy_hash: Some(policy.policy_hash.clone()),
            ..TunnelOptions::default()
        }
        .validate()
        .map_err(|error| SplitTunnelPolicyError::InvalidTunnelOptions {
            code: error.stable_code(),
        })
    };
    validate_packages(
        SplitTunnelMode::ExcludeSelected,
        &policy.mandatory_excluded_packages,
    )?;
    validate_packages(policy.mode, &policy.selected_packages)?;
    if policy.mode == SplitTunnelMode::ExcludeSelected {
        let effective_packages = policy
            .mandatory_excluded_packages
            .iter()
            .chain(policy.selected_packages.iter())
            .collect::<HashSet<_>>();
        if effective_packages.len() > MAX_SELECTED_PACKAGES {
            return Err(SplitTunnelPolicyError::SelectedPackagesLimit);
        }
    }
    DesktopTunnelOptions {
        excluded_ipv4_cidrs: policy.excluded_ipv4_cidrs.clone(),
        exclude_local_networks: policy.exclude_local_networks,
        policy_hash: Some(policy.policy_hash.clone()),
    }
    .validate()
    .map_err(|error| SplitTunnelPolicyError::InvalidTunnelOptions {
        code: error.stable_code(),
    })?;
    Ok(())
}

fn valid_normalized_domain(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || !value.contains('.')
        || !value.is_ascii()
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn normalize_address_rule_input(value: &str) -> Result<String, SplitTunnelPolicyError> {
    let candidate = value.trim();
    if candidate.is_empty()
        || candidate.len() > MAX_ADDRESS_RULE_INPUT_LENGTH
        || candidate.chars().any(char::is_control)
    {
        return Err(SplitTunnelPolicyError::InvalidAddressRule);
    }
    if !candidate.contains("://") {
        return Ok(candidate.to_string());
    }
    let parsed = Url::parse(candidate).map_err(|_| SplitTunnelPolicyError::InvalidAddressRule)?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(SplitTunnelPolicyError::InvalidAddressRule);
    }
    parsed
        .host_str()
        .filter(|host| !host.is_empty())
        .map(str::to_string)
        .ok_or(SplitTunnelPolicyError::InvalidAddressRule)
}

struct DomainResolutionOutcome {
    ipv4_cidrs: Vec<String>,
    had_failures: bool,
    missing_cache: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DomainResolutionMode {
    Refresh,
    ResolveMissing,
    CachedOnly,
}

async fn resolve_policy_domains(
    policy: &SplitTunnelPolicy,
    state: &mut StoredSplitTunnelState,
    now_unix: i64,
    mode: DomainResolutionMode,
) -> DomainResolutionOutcome {
    resolve_policy_domains_with(policy, state, now_unix, mode, resolve_domain_ipv4).await
}

async fn resolve_domain_ipv4(domain: String) -> Option<Vec<String>> {
    tokio::time::timeout(
        DNS_LOOKUP_TIMEOUT,
        tokio::net::lookup_host((domain.as_str(), 0)),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .map(|addresses| {
        let mut cidrs = addresses
            .filter_map(|address| match address.ip() {
                IpAddr::V4(address) => Some(format!("{address}/32")),
                IpAddr::V6(_) => None,
            })
            .collect::<Vec<_>>();
        cidrs.sort();
        cidrs.dedup();
        cidrs.truncate(MAX_IPV4_ADDRESSES_PER_DOMAIN);
        cidrs
    })
    .filter(|cidrs| !cidrs.is_empty())
}

async fn resolve_policy_domains_with<F, Fut>(
    policy: &SplitTunnelPolicy,
    state: &mut StoredSplitTunnelState,
    now_unix: i64,
    mode: DomainResolutionMode,
    resolver: F,
) -> DomainResolutionOutcome
where
    F: Fn(String) -> Fut + Clone,
    Fut: Future<Output = Option<Vec<String>>>,
{
    let mut domains = policy
        .address_rules
        .iter()
        .filter(|rule| rule.kind == SplitTunnelAddressRuleKind::Domain)
        .map(|rule| rule.value.clone())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    let active_domains = domains.iter().cloned().collect::<HashSet<_>>();
    let mut cached = state
        .domain_resolutions
        .drain(..)
        .filter(|item| active_domains.contains(&item.domain))
        .map(|item| (item.domain.clone(), item))
        .collect::<HashMap<_, _>>();
    let to_resolve = domains
        .iter()
        .filter(|domain| {
            mode != DomainResolutionMode::CachedOnly
                && (mode == DomainResolutionMode::Refresh || !cached.contains_key(domain.as_str()))
        })
        .cloned()
        .collect::<Vec<_>>();

    let lookups = stream::iter(to_resolve.iter().cloned().map(|domain| {
        let resolver = resolver.clone();
        async move {
            let result = resolver(domain.clone()).await.map(|mut cidrs| {
                cidrs.sort();
                cidrs.dedup();
                cidrs.truncate(MAX_IPV4_ADDRESSES_PER_DOMAIN);
                cidrs
            });
            (domain, result.filter(|cidrs| !cidrs.is_empty()))
        }
    }))
    .buffer_unordered(DNS_CONCURRENCY);
    tokio::pin!(lookups);

    let deadline = tokio::time::Instant::now() + DNS_BATCH_TIMEOUT;
    let mut successful = HashSet::new();
    while let Ok(Some((domain, result))) = tokio::time::timeout_at(deadline, lookups.next()).await {
        if let Some(ipv4_cidrs) = result {
            successful.insert(domain.clone());
            cached.insert(
                domain.clone(),
                StoredSplitTunnelDomainResolution {
                    domain,
                    ipv4_cidrs,
                    resolved_at_unix: now_unix,
                },
            );
        }
    }

    let failed_domains = to_resolve
        .iter()
        .filter(|domain| !successful.contains(domain.as_str()))
        .cloned()
        .collect::<HashSet<_>>();
    let missing_cache = domains.iter().any(|domain| !cached.contains_key(domain));
    let mut ipv4_cidrs = domains
        .iter()
        .filter_map(|domain| cached.get(domain))
        .flat_map(|item| item.ipv4_cidrs.iter().cloned())
        .collect::<Vec<_>>();
    ipv4_cidrs.sort();
    ipv4_cidrs.dedup();
    state.domain_resolutions = cached.into_values().collect();
    state
        .domain_resolutions
        .sort_by(|first, second| first.domain.cmp(&second.domain));

    DomainResolutionOutcome {
        ipv4_cidrs,
        had_failures: !failed_domains.is_empty(),
        missing_cache,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitTunnelSyncOutcome {
    Skipped,
    Unchanged,
    Updated { reconnected: bool },
    CachedOffline,
    UnsupportedPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectedPolicyApplyOutcome {
    Unchanged,
    ConfigurationUnavailable,
    AppliedWithoutReconnect,
    Applied,
    RolledBack,
    StopFailed,
    ApplyFailed,
    Failed,
}

impl ConnectedPolicyApplyOutcome {
    fn reconnected(self) -> bool {
        matches!(self, Self::Applied | Self::RolledBack | Self::Failed)
    }

    fn error_code(self) -> Option<&'static str> {
        match self {
            Self::Unchanged | Self::AppliedWithoutReconnect | Self::Applied => None,
            Self::ConfigurationUnavailable => Some("split_tunnel_saved_connection_unavailable"),
            Self::RolledBack => Some("split_tunnel_apply_failed"),
            Self::StopFailed => Some("split_tunnel_stop_failed"),
            Self::ApplyFailed => Some("split_tunnel_apply_failed"),
            Self::Failed => Some("split_tunnel_rollback_failed"),
        }
    }
}

impl<A, S, T, L> ClientCore<A, S, T, L>
where
    A: CoreApi,
    S: RuntimeStateStore,
    T: nelomai_client_tunnel::TunnelController,
    L: CoreLogger,
{
    pub fn set_split_tunnel_installed_packages(&self, packages: Vec<SplitTunnelSelectedPackage>) {
        if let Ok(mut stored) = self.split_tunnel_packages.write() {
            *stored = packages;
        }
    }

    pub async fn split_tunnel_warning(&self) -> Option<String> {
        self.split_tunnel_warning.lock().await.current()
    }

    pub fn cached_split_tunnel_policy(&self) -> Result<Option<SplitTunnelPolicy>, CoreError> {
        self.cached_policy_for_start()
    }

    pub async fn split_tunnel_capabilities(&self) -> Result<TunnelCapabilities, CoreError> {
        self.tunnel.capabilities().await.map_err(Into::into)
    }

    pub(crate) async fn initialize_physical_network_detector(
        &self,
        options: &TunnelOptions,
    ) -> Option<String> {
        self.physical_network_change.lock().await.reset();
        if !physical_network_tracking_active(options) {
            return None;
        }
        if let Ok(Some(fingerprint)) = self.tunnel.physical_network_fingerprint().await {
            self.physical_network_change
                .lock()
                .await
                .mark_applied(fingerprint.clone());
            return Some(fingerprint);
        }
        None
    }

    pub(crate) fn clear_applied_physical_network_fingerprint(&self) {
        let Ok(mut state) = self.split_tunnel_store.load() else {
            return;
        };
        state.applied_physical_network_fingerprint = None;
        let _ = self.split_tunnel_store.save(&state);
    }

    pub async fn poll_physical_network(
        &self,
        now_unix: i64,
    ) -> Result<PhysicalNetworkPollOutcome, CoreError> {
        self.poll_physical_network_guarded(now_unix, || true).await
    }

    pub async fn poll_physical_network_guarded(
        &self,
        now_unix: i64,
        allowed: impl Fn() -> bool + Send,
    ) -> Result<PhysicalNetworkPollOutcome, CoreError> {
        let cancel_epoch = crate::StartCancellationEpoch(
            self.start_cancel_epoch
                .load(std::sync::atomic::Ordering::SeqCst),
        );
        let Ok(_split_guard) = self.split_tunnel_gate.try_lock() else {
            return Ok(PhysicalNetworkPollOutcome::Busy);
        };
        let Ok(_connection_guard) = self.connection_gate.try_lock() else {
            return Ok(PhysicalNetworkPollOutcome::Busy);
        };
        let current = {
            let state = self.state.lock().await;
            self.ensure_start_not_cancelled(cancel_epoch)?;
            (state.phase == Phase::Connected)
                .then(|| state.connection.clone())
                .flatten()
        };
        let Some(connection) = current else {
            self.physical_network_change.lock().await.reset();
            return Ok(PhysicalNetworkPollOutcome::Skipped);
        };
        // The native v2 owner monitors and rebinds its entire pair. Its policy
        // recipe must never enter legacy single-member network recovery.
        if connection.session_id.is_some() || self.tunnel.owns_redundant_session().await? {
            return Ok(PhysicalNetworkPollOutcome::Skipped);
        }
        let options = {
            let running = self.split_tunnel_options.lock().await;
            running
                .is_available_for(&connection.lease_id, cancel_epoch)
                .then(|| running.options.clone())
        };
        let Some(options) = options else {
            self.physical_network_change.lock().await.reset();
            return Ok(PhysicalNetworkPollOutcome::Skipped);
        };
        if options.policy_hash.is_none()
            || (!options.exclude_local_networks && options.excluded_ipv4_cidrs.is_empty())
        {
            self.physical_network_change.lock().await.reset();
            return Ok(PhysicalNetworkPollOutcome::Skipped);
        }
        let fingerprint_result = self.tunnel.physical_network_fingerprint().await;
        self.ensure_start_not_cancelled(cancel_epoch)?;
        if !allowed() {
            return Ok(PhysicalNetworkPollOutcome::RetryDeferred);
        }
        let fingerprint = match fingerprint_result {
            Ok(Some(fingerprint)) => fingerprint,
            Ok(None) => {
                self.physical_network_change.lock().await.reset();
                return Ok(PhysicalNetworkPollOutcome::Skipped);
            }
            Err(error) => {
                let reconnect_after_recovery = probe_failure_requires_reconnect(&error);
                if self
                    .physical_network_change
                    .lock()
                    .await
                    .mark_probe_failed(reconnect_after_recovery)
                {
                    self.logger.record(crate::CoreLogEvent {
                        kind: "split_tunnel.network_probe_failed",
                        operation_id: None,
                        request_id: None,
                        code: Some(error.to_string()),
                    });
                }
                return Ok(PhysicalNetworkPollOutcome::ProbeFailed);
            }
        };
        let observation = self
            .physical_network_change
            .lock()
            .await
            .observe(fingerprint.clone(), now_unix);
        match observation {
            PhysicalNetworkObservation::BaselineRecorded => {
                return Ok(PhysicalNetworkPollOutcome::BaselineRecorded);
            }
            PhysicalNetworkObservation::ChangePending => {
                return Ok(PhysicalNetworkPollOutcome::ChangePending);
            }
            PhysicalNetworkObservation::RetryDeferred => {
                return Ok(PhysicalNetworkPollOutcome::RetryDeferred);
            }
            PhysicalNetworkObservation::Unchanged => {
                return Ok(PhysicalNetworkPollOutcome::Unchanged);
            }
            PhysicalNetworkObservation::ConfirmedChange(_) => {}
        }

        let stored = self.load_runtime()?;
        let configuration = stored
            .saved_connection
            .as_ref()
            .into_iter()
            .chain(stored.pinned_connection.as_ref())
            .find(|saved| saved.lease_id == connection.lease_id)
            .map(|saved| saved.configuration.clone());
        let Some(configuration) = configuration else {
            self.set_split_tunnel_warning(
                SplitTunnelWarningKind::Operation,
                "split_tunnel_network_reconnect_failed",
            )
            .await;
            let should_report = self
                .physical_network_change
                .lock()
                .await
                .defer_retry(now_unix);
            if should_report {
                self.logger.record(crate::CoreLogEvent {
                    kind: "split_tunnel.network_reconnect_failed",
                    operation_id: None,
                    request_id: None,
                    code: Some("saved_connection_unavailable".to_string()),
                });
            }
            return Ok(PhysicalNetworkPollOutcome::ReconnectFailed);
        };
        if !allowed() {
            return Ok(PhysicalNetworkPollOutcome::RetryDeferred);
        }
        self.retire_split_tunnel_confirmation(&connection, cancel_epoch)
            .await?;
        let stop_result = self.tunnel.stop_for_restart().await;
        self.ensure_offline_start_current(cancel_epoch).await?;
        if let Err(error) = stop_result {
            let tunnel_stopped = self
                .tunnel
                .status()
                .await
                .is_ok_and(|status| status != nelomai_client_tunnel::TunnelStatus::Running);
            let should_report = if tunnel_stopped {
                self.publish_local_recovery_phase(cancel_epoch, Phase::Stopping, &connection)
                    .await?;
                self.physical_network_change.lock().await.reset();
                true
            } else {
                self.physical_network_change
                    .lock()
                    .await
                    .defer_retry(now_unix)
            };
            self.set_split_tunnel_warning(
                SplitTunnelWarningKind::Operation,
                "split_tunnel_network_reconnect_failed",
            )
            .await;
            if should_report {
                self.logger.record(crate::CoreLogEvent {
                    kind: "split_tunnel.network_reconnect_failed",
                    operation_id: None,
                    request_id: None,
                    code: Some(error.to_string()),
                });
            }
            return Ok(PhysicalNetworkPollOutcome::ReconnectFailed);
        }
        self.publish_local_recovery_phase(cancel_epoch, Phase::Connecting, &connection)
            .await?;
        let start = |configuration: String, options: TunnelOptions| {
            self.tunnel
                .start_for_restart(nelomai_client_tunnel::TunnelStartRequest {
                    configuration: nelomai_client_tunnel::TunnelConfiguration::new(configuration),
                    options,
                    quick_reconnect: nelomai_client_tunnel::QuickReconnect::Disabled,
                    quick_connection: Some(local_restart_connection(&connection)),
                    redundancy: None,
                })
        };
        let first = start(configuration.clone(), options.clone()).await;
        self.ensure_offline_start_current(cancel_epoch).await?;
        if first.is_err() {
            let second = start(configuration, options.clone()).await;
            self.ensure_offline_start_current(cancel_epoch).await?;
            if let Err(error) = second {
                self.publish_local_recovery_phase(cancel_epoch, Phase::Stopping, &connection)
                    .await?;
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Operation,
                    "split_tunnel_network_reconnect_failed",
                )
                .await;
                self.logger.record(crate::CoreLogEvent {
                    kind: "split_tunnel.network_reconnect_failed",
                    operation_id: None,
                    request_id: None,
                    code: Some(error.to_string()),
                });
                self.physical_network_change.lock().await.reset();
                return Ok(PhysicalNetworkPollOutcome::ReconnectFailed);
            }
        }
        self.publish_recovered_split_tunnel_state(
            cancel_epoch,
            connection,
            options,
            &_connection_guard,
        )
        .await?;
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Operation)
            .await;
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
            .await;
        self.physical_network_change
            .lock()
            .await
            .mark_applied(fingerprint.clone());
        if let Ok(mut split_state) = self.split_tunnel_store.load() {
            split_state.applied_physical_network_fingerprint = Some(fingerprint);
            if self.split_tunnel_store.save(&split_state).is_err() {
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Storage,
                    "split_tunnel_state_save_failed",
                )
                .await;
            } else {
                self.clear_split_tunnel_warning(SplitTunnelWarningKind::Storage)
                    .await;
            }
        } else {
            self.set_split_tunnel_warning(
                SplitTunnelWarningKind::Storage,
                "split_tunnel_state_save_failed",
            )
            .await;
        }
        self.logger.record(crate::CoreLogEvent {
            kind: "split_tunnel.network_reconnected",
            operation_id: None,
            request_id: None,
            code: None,
        });
        Ok(PhysicalNetworkPollOutcome::Reconnected)
    }

    pub async fn recover_stalled_data_plane(
        &self,
        lease_id: &str,
        recovery: crate::StalledDataPlaneRecovery,
    ) -> Result<crate::StalledDataPlaneRecoveryOutcome, CoreError> {
        let cancel_epoch = crate::StartCancellationEpoch(
            self.start_cancel_epoch
                .load(std::sync::atomic::Ordering::SeqCst),
        );
        let Ok(_intent_recovery_guard) = self.intent_recovery_gate.try_lock() else {
            return Ok(crate::StalledDataPlaneRecoveryOutcome::Busy);
        };
        let Ok(_split_guard) = self.split_tunnel_gate.try_lock() else {
            return Ok(crate::StalledDataPlaneRecoveryOutcome::Busy);
        };
        let Ok(_connection_guard) = self.connection_gate.try_lock() else {
            return Ok(crate::StalledDataPlaneRecoveryOutcome::Busy);
        };
        let connection = {
            let state = self.state.lock().await;
            self.ensure_start_not_cancelled(cancel_epoch)?;
            (state.phase == Phase::Connected)
                .then(|| state.connection.clone())
                .flatten()
                .filter(|connection| connection.lease_id == lease_id)
        };
        let Some(connection) = connection else {
            return Ok(crate::StalledDataPlaneRecoveryOutcome::Skipped);
        };
        if recovery == crate::StalledDataPlaneRecovery::RebindUdp {
            let rebound =
                tokio::time::timeout(std::time::Duration::from_secs(3), self.tunnel.rebind_udp())
                    .await
                    .map_err(|_| CoreError::Tunnel("udp_rebind_timeout".to_string()))??;
            self.ensure_start_not_cancelled(cancel_epoch)?;
            return Ok(if rebound {
                crate::StalledDataPlaneRecoveryOutcome::Rebound
            } else {
                crate::StalledDataPlaneRecoveryOutcome::Unsupported
            });
        }

        let stored = self.load_runtime()?;
        let configuration = stored
            .saved_connection
            .as_ref()
            .into_iter()
            .chain(stored.pinned_connection.as_ref())
            .find(|saved| saved.lease_id == lease_id)
            .map(|saved| saved.configuration.clone());
        let Some(configuration) = configuration else {
            return Ok(crate::StalledDataPlaneRecoveryOutcome::Skipped);
        };
        let options = {
            let running = self.split_tunnel_options.lock().await;
            if !running.is_available_for(&connection.lease_id, cancel_epoch) {
                // Failed restoration is not a genuine default plan. Leave the
                // running owner untouched until its options can be recovered.
                return Ok(crate::StalledDataPlaneRecoveryOutcome::Skipped);
            }
            running.options.clone()
        };
        self.begin_recovery_episode(
            &connection,
            crate::ConnectOptions {
                layer: connection.layer,
                tic_connection_mode: connection.tic_connection_mode,
                route_mode: connection.route_mode,
                egress_mode: connection.egress_mode,
                probes: Vec::new(),
                allow_alternate: !connection.pinned
                    && connection.tic_connection_mode
                        == nelomai_contracts::TicConnectionMode::Dynamic,
            },
        )
        .await;
        let transport =
            nelomai_client_tunnel::TunnelConfiguration::new(configuration.clone()).transport();
        self.retire_split_tunnel_confirmation(&connection, cancel_epoch)
            .await?;
        let stop_result = self.tunnel.stop_for_restart().await;
        self.ensure_offline_start_current(cancel_epoch).await?;
        if let Err(error) = stop_result {
            if !matches!(
                self.tunnel.status().await,
                Ok(nelomai_client_tunnel::TunnelStatus::Stopped
                    | nelomai_client_tunnel::TunnelStatus::Failed)
            ) {
                return Err(error.into());
            }
        }
        self.publish_local_recovery_phase(cancel_epoch, Phase::Connecting, &connection)
            .await?;
        let start = || {
            self.tunnel
                .start_for_restart(nelomai_client_tunnel::TunnelStartRequest {
                    configuration: nelomai_client_tunnel::TunnelConfiguration::new(
                        configuration.clone(),
                    ),
                    options: options.clone(),
                    quick_reconnect: nelomai_client_tunnel::QuickReconnect::Disabled,
                    quick_connection: Some(local_restart_connection(&connection)),
                    redundancy: None,
                })
        };
        let first_start_result = start().await;
        self.ensure_offline_start_current(cancel_epoch).await?;
        let start_result = if first_start_result.is_err() {
            self.logger.record(crate::CoreLogEvent {
                kind: "tunnel.stall.local_start_retry",
                operation_id: None,
                request_id: None,
                code: first_start_result.as_ref().err().map(ToString::to_string),
            });
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            self.ensure_start_not_cancelled(cancel_epoch)?;
            start().await
        } else {
            first_start_result
        };
        self.ensure_offline_start_current(cancel_epoch).await?;
        if let Err(error) = start_result {
            self.publish_local_recovery_phase(cancel_epoch, Phase::Stopping, &connection)
                .await?;
            return Err(error.into());
        }
        if transport == nelomai_client_tunnel::TunnelTransport::AmneziaWg3 {
            if let Err(error) = self
                .ensure_awg3_handshake(lease_id, None, Some(cancel_epoch))
                .await
            {
                self.ensure_start_not_cancelled(cancel_epoch)?;
                let cleanup_error = self.tunnel.stop().await.err().map(CoreError::from);
                self.publish_local_recovery_phase(cancel_epoch, Phase::Stopping, &connection)
                    .await?;
                return Err(cleanup_error.unwrap_or(error));
            }
        }
        self.publish_recovered_split_tunnel_state(
            cancel_epoch,
            connection,
            options,
            &_connection_guard,
        )
        .await?;
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
            .await;
        *self.active_recovery_episode.lock().await = None;
        Ok(crate::StalledDataPlaneRecoveryOutcome::Reconnected)
    }

    async fn publish_local_recovery_phase(
        &self,
        cancel_epoch: crate::StartCancellationEpoch,
        phase: Phase,
        connection: &Connection,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().await;
        if self.ensure_start_not_cancelled(cancel_epoch).is_err() {
            drop(state);
            return self.ensure_offline_start_current(cancel_epoch).await;
        }
        if !state
            .connection
            .as_ref()
            .is_some_and(|current| same_local_recovery_execution(current, connection))
        {
            return Err(CoreError::StartCancelled);
        }
        // Bootstrap may have enriched this same execution since it was
        // captured. Change only its phase, not its newer observed metadata.
        state.phase = phase;
        Ok(())
    }

    async fn retire_split_tunnel_confirmation(
        &self,
        connection: &Connection,
        cancel_epoch: crate::StartCancellationEpoch,
    ) -> Result<(), CoreError> {
        let state = self.state.lock().await;
        let mut running = self.split_tunnel_options.lock().await;
        self.ensure_start_not_cancelled(cancel_epoch)?;
        if state.phase != Phase::Connected
            || !state
                .connection
                .as_ref()
                .is_some_and(|current| same_local_recovery_execution(current, connection))
        {
            return Err(CoreError::StartCancelled);
        }
        // Once native replacement begins, the previous instance may be gone.
        // Keep its options for retry, but only success can confirm them again.
        running.native_confirmed = false;
        Ok(())
    }

    async fn publish_recovered_split_tunnel_state(
        &self,
        cancel_epoch: crate::StartCancellationEpoch,
        connection: nelomai_contracts::Connection,
        options: TunnelOptions,
        _connection_guard: &tokio::sync::MutexGuard<'_, ()>,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().await;
        let mut running = self.split_tunnel_options.lock().await;
        if self.ensure_start_not_cancelled(cancel_epoch).is_err() {
            drop(running);
            drop(state);
            return self.ensure_offline_start_current(cancel_epoch).await;
        }
        if !state
            .connection
            .as_ref()
            .is_some_and(|current| same_local_recovery_execution(current, &connection))
        {
            let rejected_state = state.clone();
            drop(running);
            drop(state);
            // This operation still holds the connection gate, so another Core
            // Start cannot have replaced its dispatched transport. Independent
            // native owners are fenced again when executing legacy-only Stop.
            let cleanup = self.tunnel.stop_if_unowned().await;
            if cleanup.is_err()
                && self
                    .tunnel
                    .owns_redundant_session()
                    .await
                    .is_ok_and(|owned| owned)
            {
                return Err(CoreError::StartCancelled);
            }
            let mut state = self.state.lock().await;
            *self.split_tunnel_options.lock().await = RunningSplitTunnelOptions::default();
            // Preserve newer metadata and a concurrent Stop's presentation.
            if self.ensure_start_not_cancelled(cancel_epoch).is_ok() && *state == rejected_state {
                state.phase = if cleanup.is_ok() {
                    Phase::Stopping
                } else {
                    Phase::Error
                };
            }
            cleanup.map_err(CoreError::from)?;
            return Err(CoreError::StartCancelled);
        }
        // Only a successful native restart attests to the exact dispatched
        // options. Publish that attestation with the same owner/generation.
        *running =
            RunningSplitTunnelOptions::confirmed(options, &connection.lease_id, cancel_epoch);
        state.phase = Phase::Connected;
        Ok(())
    }

    pub async fn split_tunnel_settings_require_reconnect(
        &self,
        request: &SplitTunnelSettingsUpdate,
    ) -> Result<bool, CoreError> {
        let current = {
            let state = self.state.lock().await;
            (state.phase == Phase::Connected)
                .then(|| state.connection.clone())
                .flatten()
        };
        let Some(connection) = current else {
            return Ok(false);
        };
        let capabilities = self.tunnel.capabilities().await?;
        // These Android versions ignore split options at the native boundary;
        // preference changes cannot require replacement of the live tunnel.
        if capabilities.platform == TunnelPlatform::Android
            && capabilities
                .android_api_level
                .is_some_and(|level| level <= 32)
        {
            return Ok(false);
        }
        let running = self.split_tunnel_options.lock().await.clone();
        let confirmed = running.is_confirmed_for(
            &connection.lease_id,
            crate::StartCancellationEpoch(
                self.start_cancel_epoch
                    .load(std::sync::atomic::Ordering::SeqCst),
            ),
        );
        // A stored working hash is not an attestation of an independently
        // started Android tunnel. A save may require a replacement even when
        // the request is identical to the cache, so obtain confirmation first.
        if capabilities.platform == TunnelPlatform::Android && !confirmed {
            return Ok(true);
        }
        let Some(policy) = self.cached_policy_for_start()? else {
            return Ok(false);
        };
        let packages = self
            .split_tunnel_packages
            .read()
            .map(|packages| packages.clone())
            .unwrap_or_default();
        let stored = self
            .split_tunnel_store
            .load()
            .map_err(|_| CoreError::Storage)?;
        // Compare using last-good addresses for exactly the domains still in
        // the policy. Preflight is observational and must not perform DNS I/O.
        let resolved_domains = policy
            .address_rules
            .iter()
            .filter(|rule| rule.kind == SplitTunnelAddressRuleKind::Domain)
            .flat_map(|rule| {
                stored
                    .domain_resolutions
                    .iter()
                    .filter(move |item| item.domain == rule.value)
            })
            .flat_map(|item| item.ipv4_cidrs.iter().cloned())
            .collect::<Vec<_>>();
        let current = EffectiveSplitTunnelPolicy::build_with_resolved_domains(
            &policy,
            &packages,
            capabilities,
            connection.layer,
            connection.route_mode,
            &resolved_domains,
        )
        .map_err(|error| CoreError::SplitTunnel(error.stable_code().to_string()))?;
        let mut proposed = policy;
        proposed.mode = request.mode;
        proposed.exclude_local_networks = request.exclude_local_networks;
        proposed.selected_packages = request
            .selected_packages
            .iter()
            .map(|package| package.package_id.clone())
            .collect();
        let proposed = EffectiveSplitTunnelPolicy::build_with_resolved_domains(
            &proposed,
            &packages,
            capabilities,
            connection.layer,
            connection.route_mode,
            &resolved_domains,
        )
        .map_err(|error| CoreError::SplitTunnel(error.stable_code().to_string()))?;
        let current = if confirmed {
            &running.options
        } else {
            &current.options
        };
        Ok(!current.has_same_effective_routes(&proposed.options))
    }

    pub async fn reset_split_tunnel_state(&self) -> Result<(), CoreError> {
        let _guard = self.split_tunnel_gate.lock().await;
        self.split_tunnel_store
            .delete()
            .map_err(|_| CoreError::Storage)?;
        if let Ok(mut packages) = self.split_tunnel_packages.write() {
            packages.clear();
        }
        *self.split_tunnel_options.lock().await = RunningSplitTunnelOptions::default();
        self.clear_all_split_tunnel_warnings().await;
        self.physical_network_change.lock().await.reset();
        Ok(())
    }

    pub async fn synchronize_split_tunnel(
        &self,
        now_unix: i64,
        force_full: bool,
    ) -> Result<SplitTunnelSyncOutcome, CoreError> {
        let _guard = self.split_tunnel_gate.lock().await;
        let mut state = self
            .split_tunnel_store
            .load()
            .map_err(|_| CoreError::Storage)?;
        if !force_full
            && state
                .last_revision_check_unix
                .is_some_and(|last| now_unix.saturating_sub(last) < REVISION_POLL_SECONDS)
        {
            return Ok(SplitTunnelSyncOutcome::Skipped);
        }

        let mut access_token = self.access_snapshot().await?;
        self.flush_pending_apply_results(&mut access_token, &mut state)
            .await;
        let revision = match self.request_split_tunnel_revision(&mut access_token).await {
            Ok(revision) => revision,
            Err(CoreError::Api(CoreApiError::Retryable)) => {
                state.last_revision_check_unix = Some(now_unix);
                self.split_tunnel_store
                    .save(&state)
                    .map_err(|_| CoreError::Storage)?;
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Sync,
                    "split_tunnel_cached_offline",
                )
                .await;
                return Ok(SplitTunnelSyncOutcome::CachedOffline);
            }
            Err(error) => return Err(error),
        };

        let force_revision_changed = revision.force_revision > state.last_seen_force_revision;
        let address_revision_changed =
            revision.address_revision != state.last_seen_address_revision;
        let full_sync_due = force_full
            || state.cached_policy.is_none()
            || state
                .last_full_sync_unix
                .is_none_or(|last| now_unix.saturating_sub(last) >= FULL_SYNC_SECONDS)
            || state.cached_policy.as_ref().is_some_and(|policy| {
                policy.revision != revision.revision || policy.enabled != revision.enabled
            })
            || force_revision_changed
            || address_revision_changed;
        state.last_revision_check_unix = Some(now_unix);
        if !full_sync_due {
            state.last_seen_force_revision = revision.force_revision;
            state.last_seen_address_revision = revision.address_revision;
            let needs_retry = self.connected_connection().await.is_some()
                && state.cached_policy.as_ref().is_some_and(|policy| {
                    state.working_policy_hash.as_deref() != Some(policy.policy_hash.as_str())
                        && policy_retry_due(&state, policy, now_unix)
                });
            if let Some(policy) = needs_retry.then(|| state.cached_policy.clone()).flatten() {
                let outcome = self
                    .apply_policy_if_connected(
                        &policy,
                        &mut state,
                        &mut access_token,
                        now_unix,
                        DomainResolutionMode::Refresh,
                    )
                    .await?;
                self.split_tunnel_store
                    .save(&state)
                    .map_err(|_| CoreError::Storage)?;
                return Ok(SplitTunnelSyncOutcome::Updated {
                    reconnected: outcome.reconnected(),
                });
            }
            self.split_tunnel_store
                .save(&state)
                .map_err(|_| CoreError::Storage)?;
            if state.cached_policy.as_ref().is_none_or(|policy| {
                state.working_policy_hash.as_deref() == Some(policy.policy_hash.as_str())
            }) {
                self.clear_split_tunnel_warning(SplitTunnelWarningKind::Sync)
                    .await;
            }
            return Ok(SplitTunnelSyncOutcome::Unchanged);
        }

        let policy = match self.request_split_tunnel_policy(&mut access_token).await {
            Ok(policy) => policy,
            Err(CoreError::Api(CoreApiError::Retryable)) => {
                self.split_tunnel_store
                    .save(&state)
                    .map_err(|_| CoreError::Storage)?;
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Sync,
                    "split_tunnel_cached_offline",
                )
                .await;
                return Ok(SplitTunnelSyncOutcome::CachedOffline);
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = validate_split_tunnel_policy(&policy) {
            self.split_tunnel_store
                .save(&state)
                .map_err(|_| CoreError::Storage)?;
            self.set_split_tunnel_warning(SplitTunnelWarningKind::Sync, error.stable_code())
                .await;
            return Ok(SplitTunnelSyncOutcome::UnsupportedPolicy);
        }

        let changed = state
            .cached_policy
            .as_ref()
            .is_none_or(|cached| cached.policy_hash != policy.policy_hash);
        remember_previous_working_policy(&mut state);
        clear_stale_policy_failure(&mut state, &policy);
        state.cached_policy = Some(policy.clone());
        state.last_full_sync_unix = Some(now_unix);
        state.last_seen_force_revision = revision.force_revision;
        state.last_seen_address_revision = revision.address_revision;
        self.split_tunnel_store
            .save(&state)
            .map_err(|_| CoreError::Storage)?;
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Sync)
            .await;
        let needs_apply = force_full
            || changed
            || state.working_policy_hash.as_deref() != Some(policy.policy_hash.as_str())
            || policy
                .address_rules
                .iter()
                .any(|rule| rule.kind == SplitTunnelAddressRuleKind::Domain);
        let outcome = if needs_apply {
            self.apply_policy_if_connected(
                &policy,
                &mut state,
                &mut access_token,
                now_unix,
                DomainResolutionMode::Refresh,
            )
            .await?
        } else {
            ConnectedPolicyApplyOutcome::Unchanged
        };
        self.split_tunnel_store
            .save(&state)
            .map_err(|_| CoreError::Storage)?;
        Ok(SplitTunnelSyncOutcome::Updated {
            reconnected: outcome.reconnected(),
        })
    }

    pub async fn save_split_tunnel_settings(
        &self,
        request: &SplitTunnelSettingsUpdate,
        now_unix: i64,
    ) -> Result<SplitTunnelPolicy, CoreError> {
        let _guard = self.split_tunnel_gate.lock().await;
        let mut state = self
            .split_tunnel_store
            .load()
            .map_err(|_| CoreError::Storage)?;
        let mut access_token = self.access_snapshot().await?;
        self.flush_pending_apply_results(&mut access_token, &mut state)
            .await;
        let policy = self
            .request_split_tunnel_settings(&mut access_token, request)
            .await?;
        validate_split_tunnel_policy(&policy)
            .map_err(|error| CoreError::SplitTunnel(error.stable_code().to_string()))?;
        let changed = state
            .cached_policy
            .as_ref()
            .is_none_or(|cached| cached.policy_hash != policy.policy_hash);
        remember_previous_working_policy(&mut state);
        clear_stale_policy_failure(&mut state, &policy);
        state.cached_policy = Some(policy.clone());
        state.last_full_sync_unix = Some(now_unix);
        state.last_revision_check_unix = Some(now_unix);
        state.last_seen_force_revision = policy.force_revision;
        state.last_seen_address_revision = policy.address_revision;
        self.split_tunnel_store
            .save(&state)
            .map_err(|_| CoreError::Storage)?;
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Sync)
            .await;
        let needs_apply = changed
            || state.working_policy_hash.as_deref() != Some(policy.policy_hash.as_str())
            // Explicit Save must check the live plan even when the cache and
            // working hash agree: both can predate a native background Start.
            || self.state.lock().await.phase == Phase::Connected;
        let outcome = if needs_apply {
            // Settings preflight compares cached domain addresses. Refreshing
            // them here could introduce an unconfirmed route replacement.
            self.apply_policy_if_connected(
                &policy,
                &mut state,
                &mut access_token,
                now_unix,
                DomainResolutionMode::CachedOnly,
            )
            .await?
        } else {
            ConnectedPolicyApplyOutcome::Unchanged
        };
        self.split_tunnel_store
            .save(&state)
            .map_err(|_| CoreError::Storage)?;
        if let Some(code) = outcome.error_code() {
            return Err(CoreError::SplitTunnel(code.to_string()));
        }
        Ok(policy)
    }

    pub async fn add_split_tunnel_address_rule(
        &self,
        request: &SplitTunnelAddressRuleUpdate,
        now_unix: i64,
    ) -> Result<SplitTunnelPolicy, CoreError> {
        let _guard = self.split_tunnel_gate.lock().await;
        let normalized_request = SplitTunnelAddressRuleUpdate {
            value: normalize_address_rule_input(&request.value)
                .map_err(|error| CoreError::SplitTunnel(error.stable_code().to_string()))?,
            scope: request.scope,
        };
        let mut state = self
            .split_tunnel_store
            .load()
            .map_err(|_| CoreError::Storage)?;
        let mut access_token = self.access_snapshot().await?;
        self.flush_pending_apply_results(&mut access_token, &mut state)
            .await;
        let policy = self
            .request_add_split_tunnel_address_rule(&mut access_token, &normalized_request)
            .await?;
        self.apply_updated_address_rule_policy(policy, &mut state, &mut access_token, now_unix)
            .await
    }

    pub async fn remove_split_tunnel_address_rule(
        &self,
        rule_id: i64,
        scope: SplitTunnelAddressRuleScope,
        now_unix: i64,
    ) -> Result<SplitTunnelPolicy, CoreError> {
        let _guard = self.split_tunnel_gate.lock().await;
        let mut state = self
            .split_tunnel_store
            .load()
            .map_err(|_| CoreError::Storage)?;
        let mut access_token = self.access_snapshot().await?;
        self.flush_pending_apply_results(&mut access_token, &mut state)
            .await;
        let policy = self
            .request_remove_split_tunnel_address_rule(&mut access_token, rule_id, scope)
            .await?;
        self.apply_updated_address_rule_policy(policy, &mut state, &mut access_token, now_unix)
            .await
    }

    async fn apply_updated_address_rule_policy(
        &self,
        policy: SplitTunnelPolicy,
        state: &mut StoredSplitTunnelState,
        access_token: &mut AccessSnapshot,
        now_unix: i64,
    ) -> Result<SplitTunnelPolicy, CoreError> {
        validate_split_tunnel_policy(&policy)
            .map_err(|error| CoreError::SplitTunnel(error.stable_code().to_string()))?;
        remember_previous_working_policy(state);
        clear_stale_policy_failure(state, &policy);
        state.cached_policy = Some(policy.clone());
        state.last_full_sync_unix = Some(now_unix);
        state.last_revision_check_unix = Some(now_unix);
        state.last_seen_force_revision = policy.force_revision;
        state.last_seen_address_revision = policy.address_revision;
        self.split_tunnel_store
            .save(state)
            .map_err(|_| CoreError::Storage)?;
        let outcome = self
            .apply_policy_if_connected(
                &policy,
                state,
                access_token,
                now_unix,
                DomainResolutionMode::Refresh,
            )
            .await?;
        self.split_tunnel_store
            .save(state)
            .map_err(|_| CoreError::Storage)?;
        if let Some(code) = outcome.error_code() {
            return Err(CoreError::SplitTunnel(code.to_string()));
        }
        Ok(policy)
    }

    async fn effective_tunnel_options_with_state(
        &self,
        policy: &SplitTunnelPolicy,
        layer: Layer,
        route_mode: RouteMode,
        state: &mut StoredSplitTunnelState,
        now_unix: i64,
        domain_resolution: DomainResolutionMode,
    ) -> Result<TunnelOptions, CoreError> {
        let capabilities = self.tunnel.capabilities().await?;
        let packages = self
            .split_tunnel_packages
            .read()
            .map(|packages| packages.clone())
            .unwrap_or_default();
        let address_rules_active = capabilities.address_split_tunnel
            && split_tunnel_active(SplitTunnelContext {
                global_enabled: policy.enabled,
                platform: capabilities.platform,
                android_api_level: capabilities.android_api_level,
                layer,
                route_mode,
            });
        let resolved_domains = if address_rules_active {
            let outcome = resolve_policy_domains(policy, state, now_unix, domain_resolution).await;
            if outcome.missing_cache {
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Dns,
                    "split_tunnel_domain_resolution_unavailable",
                )
                .await;
            } else if outcome.had_failures {
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Dns,
                    "split_tunnel_domain_resolution_failed",
                )
                .await;
            } else {
                self.clear_split_tunnel_warning(SplitTunnelWarningKind::Dns)
                    .await;
            }
            if outcome.missing_cache {
                return Err(CoreError::SplitTunnel(
                    SplitTunnelPolicyError::DomainResolutionUnavailable
                        .stable_code()
                        .to_string(),
                ));
            }
            outcome.ipv4_cidrs
        } else {
            state.domain_resolutions.clear();
            self.clear_split_tunnel_warning(SplitTunnelWarningKind::Dns)
                .await;
            Vec::new()
        };
        EffectiveSplitTunnelPolicy::build_with_resolved_domains(
            policy,
            &packages,
            capabilities,
            layer,
            route_mode,
            &resolved_domains,
        )
        .map(|effective| self.with_dns_servers(effective.options))
        .map_err(|error| CoreError::SplitTunnel(error.stable_code().to_string()))
    }

    pub(crate) async fn effective_tunnel_options(
        &self,
        policy: &SplitTunnelPolicy,
        layer: Layer,
        route_mode: RouteMode,
        now_unix: i64,
        refresh_domains: bool,
    ) -> Result<TunnelOptions, CoreError> {
        let mut state = self
            .split_tunnel_store
            .load()
            .map_err(|_| CoreError::Storage)?;
        let result = self
            .effective_tunnel_options_with_state(
                policy,
                layer,
                route_mode,
                &mut state,
                now_unix,
                if refresh_domains {
                    DomainResolutionMode::Refresh
                } else {
                    DomainResolutionMode::ResolveMissing
                },
            )
            .await;
        if self.split_tunnel_store.save(&state).is_err() {
            self.set_split_tunnel_warning(
                SplitTunnelWarningKind::Storage,
                "split_tunnel_state_save_failed",
            )
            .await;
        } else {
            self.clear_split_tunnel_warning(SplitTunnelWarningKind::Storage)
                .await;
        }
        result
    }

    pub async fn connection_intent_tunnel_options(
        &self,
        layer: Layer,
        route_mode: RouteMode,
        now_unix: i64,
    ) -> Result<TunnelOptions, CoreError> {
        match self.cached_policy_for_start()? {
            Some(policy) => {
                self.effective_tunnel_options(&policy, layer, route_mode, now_unix, false)
                    .await
            }
            None => self.fallback_tunnel_options().await,
        }
    }

    pub(crate) async fn fallback_tunnel_options(&self) -> Result<TunnelOptions, CoreError> {
        let windows = self.tunnel.capabilities().await?.platform == TunnelPlatform::Windows;
        // The Windows warning describes a running VPN. Publish it only after
        // Start succeeds (or a running tunnel is restored), not during preflight.
        if !windows {
            self.set_split_tunnel_warning(
                SplitTunnelWarningKind::Sync,
                "split_tunnel_policy_unavailable",
            )
            .await;
        }
        Ok(self.with_dns_servers(TunnelOptions {
            exclude_local_networks: windows,
            ..TunnelOptions::default()
        }))
    }

    pub(crate) async fn record_started_split_tunnel_policy(
        &self,
        policy: &SplitTunnelPolicy,
        applied: RunningSplitTunnelOptions,
        applied_physical_network_fingerprint: Option<String>,
        access_token: Option<&mut AccessSnapshot>,
        now_unix: i64,
    ) -> Result<(), CoreError> {
        let options = applied.options.clone();
        *self.split_tunnel_options.lock().await = applied;
        let mut state = self
            .split_tunnel_store
            .load()
            .map_err(|_| CoreError::Storage)?;
        state.applied_physical_network_fingerprint = applied_physical_network_fingerprint;
        if options.policy_hash.is_none() {
            return self
                .split_tunnel_store
                .save(&state)
                .map_err(|_| CoreError::Storage);
        }
        remember_previous_working_policy(&mut state);
        state.working_policy_hash = Some(policy.policy_hash.clone());
        self.split_tunnel_store
            .save(&state)
            .map_err(|_| CoreError::Storage)?;
        let result = SplitTunnelApplyResult {
            format_version: policy.format_version,
            revision: policy.revision,
            force_revision: policy.force_revision,
            address_revision: policy.address_revision,
            policy_hash: policy.policy_hash.clone(),
            status: SplitTunnelApplyStatus::Applied,
            error_code: None,
            applied_at: rfc3339(now_unix)?,
        };
        if let Some(access_token) = access_token {
            self.flush_pending_apply_results(access_token, &mut state)
                .await;
            self.report_or_queue_apply_result(access_token, &mut state, result)
                .await;
        } else {
            state.pending_apply_results.push(result);
        }
        self.split_tunnel_store
            .save(&state)
            .map_err(|_| CoreError::Storage)
    }

    pub(crate) async fn retry_pending_split_tunnel_results(&self) {
        let _guard = self.split_tunnel_gate.lock().await;
        let Ok(mut state) = self.split_tunnel_store.load() else {
            return;
        };
        if state.pending_apply_results.is_empty() {
            return;
        }
        let Ok(mut access_token) = self.access_snapshot().await else {
            return;
        };
        self.flush_pending_apply_results(&mut access_token, &mut state)
            .await;
        let _ = self.split_tunnel_store.save(&state);
    }

    pub(crate) fn cached_policy_for_start(&self) -> Result<Option<SplitTunnelPolicy>, CoreError> {
        let state = self
            .split_tunnel_store
            .load()
            .map_err(|_| CoreError::Storage)?;
        let failed_cached_policy = state
            .cached_policy
            .as_ref()
            .zip(state.failed_policy_hash.as_deref())
            .is_some_and(|(policy, failed_hash)| policy.policy_hash == failed_hash);
        if failed_cached_policy {
            if let Some(policy) = working_policy(&state)
                .filter(|policy| validate_split_tunnel_policy(policy).is_ok())
                .cloned()
            {
                return Ok(Some(policy));
            }
        }
        Ok(state
            .cached_policy
            .filter(|policy| validate_split_tunnel_policy(policy).is_ok())
            .or_else(|| {
                state
                    .previous_working_policy
                    .filter(|policy| validate_split_tunnel_policy(policy).is_ok())
            }))
    }

    async fn apply_policy_if_connected(
        &self,
        policy: &SplitTunnelPolicy,
        state: &mut StoredSplitTunnelState,
        access_token: &mut AccessSnapshot,
        now_unix: i64,
        domain_resolution: DomainResolutionMode,
    ) -> Result<ConnectedPolicyApplyOutcome, CoreError> {
        let cancel_epoch = crate::StartCancellationEpoch(
            self.start_cancel_epoch
                .load(std::sync::atomic::Ordering::SeqCst),
        );
        let current = {
            let current_state = self.state.lock().await;
            (current_state.phase == Phase::Connected)
                .then(|| current_state.connection.clone())
                .flatten()
        };
        let Some(connection) = current else {
            return Ok(ConnectedPolicyApplyOutcome::Unchanged);
        };
        let stored = self.load_runtime()?;
        let configuration = stored
            .saved_connection
            .as_ref()
            .into_iter()
            .chain(stored.pinned_connection.as_ref())
            .find(|saved| saved.lease_id == connection.lease_id)
            .map(|saved| saved.configuration.clone());
        // Plan construction prunes domain addresses. Keep independent input
        // snapshots so the proposed policy cannot consume rollback data; only
        // publish the cache belonging to the plan that is actually applied.
        let mut proposed_state = state.clone();
        let mut previous_state = state.clone();
        let new_options = match self
            .effective_tunnel_options_with_state(
                policy,
                connection.layer,
                connection.route_mode,
                &mut proposed_state,
                now_unix,
                domain_resolution,
            )
            .await
        {
            Ok(options) => options,
            Err(CoreError::SplitTunnel(code)) => {
                self.set_split_tunnel_warning(SplitTunnelWarningKind::Sync, code)
                    .await;
                mark_policy_failure(state, policy, now_unix);
                return Ok(ConnectedPolicyApplyOutcome::Unchanged);
            }
            Err(error) => return Err(error),
        };
        let native_owned =
            connection.session_id.is_some() || self.tunnel.owns_redundant_session().await?;
        let previous = self.split_tunnel_options.lock().await.clone();
        let mut previous_options = if previous.is_available_for(&connection.lease_id, cancel_epoch)
        {
            previous.options.clone()
        } else {
            TunnelOptions::default()
        };
        // Owned default options are a real plan too. Only unavailable plans
        // may be reconstructed from persistent working-policy state.
        if !native_owned && !previous.is_available_for(&connection.lease_id, cancel_epoch) {
            if let Some(working_policy) = working_policy(state).cloned() {
                previous_options = match self
                    .effective_tunnel_options_with_state(
                        &working_policy,
                        connection.layer,
                        connection.route_mode,
                        &mut previous_state,
                        now_unix,
                        if domain_resolution == DomainResolutionMode::CachedOnly {
                            DomainResolutionMode::CachedOnly
                        } else {
                            DomainResolutionMode::ResolveMissing
                        },
                    )
                    .await
                {
                    Ok(options) => options,
                    Err(CoreError::SplitTunnel(code)) => {
                        // Replacement needs a known rollback plan. Do not
                        // turn a missing domain cache into default routes.
                        self.set_split_tunnel_warning(SplitTunnelWarningKind::Sync, code)
                            .await;
                        mark_policy_failure(state, policy, now_unix);
                        return Ok(ConnectedPolicyApplyOutcome::Unchanged);
                    }
                    Err(error) => return Err(error),
                };
            }
        }
        let inactive_android_split = new_options
            .has_same_effective_routes(&TunnelOptions::default())
            && matches!(self.tunnel.capabilities().await?, capabilities
                if capabilities.platform == TunnelPlatform::Android
                    && capabilities.android_api_level.is_some_and(|level| level <= 32));
        let _connection_guard = self.connection_gate.lock().await;
        let connection_is_still_current = {
            let current_state = self.state.lock().await;
            self.ensure_start_not_cancelled(cancel_epoch)?;
            current_state.phase == Phase::Connected
                && current_state
                    .connection
                    .as_ref()
                    .is_some_and(|current| same_local_recovery_execution(current, &connection))
        };
        if !connection_is_still_current {
            return Ok(ConnectedPolicyApplyOutcome::Unchanged);
        }
        if !native_owned
            && new_options.has_same_effective_routes(&previous_options)
            && (previous.is_confirmed_for(&connection.lease_id, cancel_epoch)
                || inactive_android_split)
        {
            // No native action occurred. Retain the actual dispatched options,
            // including DNS and native hash; only policy bookkeeping changes.
            // Inactive Android split also must not attest reconstructed options.
            state.domain_resolutions = proposed_state.domain_resolutions;
            state.working_policy_hash = Some(policy.policy_hash.clone());
            clear_policy_failure(state);
            if self.split_tunnel_store.save(state).is_err() {
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Storage,
                    "split_tunnel_state_save_failed",
                )
                .await;
            } else {
                self.clear_split_tunnel_warning(SplitTunnelWarningKind::Storage)
                    .await;
            }
            self.clear_split_tunnel_warning(SplitTunnelWarningKind::Operation)
                .await;
            let result = SplitTunnelApplyResult {
                format_version: policy.format_version,
                revision: policy.revision,
                force_revision: policy.force_revision,
                address_revision: policy.address_revision,
                policy_hash: policy.policy_hash.clone(),
                status: SplitTunnelApplyStatus::Applied,
                error_code: None,
                applied_at: rfc3339(now_unix)?,
            };
            self.report_or_queue_apply_result(access_token, state, result)
                .await;
            return Ok(ConnectedPolicyApplyOutcome::AppliedWithoutReconnect);
        }

        // A Windows connection started without policy is deliberately local-only.
        // Cache the downloaded policy, but don't recreate a working VPN behind
        // the user's back. The next explicit Start consumes the cache normally.
        if !native_owned
            && previous_options.policy_hash.is_none()
            && previous_options.exclude_local_networks
        {
            // Policy application is still pending even when runtime health is
            // good. Ordinary status polling must not dismiss this warning.
            self.set_split_tunnel_warning(
                SplitTunnelWarningKind::Operation,
                "split_tunnel_policy_deferred",
            )
            .await;
            return Ok(ConnectedPolicyApplyOutcome::Unchanged);
        }
        if native_owned {
            let Some(session_id) = connection.session_id.clone() else {
                // An independently owned pair without an exact Core session scope
                // must never fall through to a legacy single-member restart.
                mark_policy_failure(state, policy, now_unix);
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Operation,
                    "split_tunnel_saved_connection_unavailable",
                )
                .await;
                self.report_policy_apply_outcome(
                    policy,
                    state,
                    access_token,
                    now_unix,
                    SplitTunnelApplyStatus::Failed,
                    Some("split_tunnel_saved_connection_unavailable".into()),
                )
                .await?;
                return Ok(ConnectedPolicyApplyOutcome::ConfigurationUnavailable);
            };
            self.retire_split_tunnel_confirmation(&connection, cancel_epoch)
                .await?;
            let result = self
                .tunnel
                .apply_owned_redundant_policy(OwnedRedundantPolicyRequest {
                    session_id,
                    connection: local_restart_connection(&connection),
                    options: new_options.clone(),
                })
                .await;
            // Native fences this operation to the captured pair. A late reply
            // must not use legacy/global Stop compensation against a newer owner.
            self.ensure_start_not_cancelled(cancel_epoch)?;
            let (outcome, status) = match result {
                Ok(
                    native_outcome @ (OwnedRedundantPolicyOutcome::Applied
                    | OwnedRedundantPolicyOutcome::Unchanged),
                ) => {
                    self.publish_owned_policy_state(
                        cancel_epoch,
                        &connection,
                        Phase::Connected,
                        Some(RunningSplitTunnelOptions::confirmed(
                            new_options.clone(),
                            &connection.lease_id,
                            cancel_epoch,
                        )),
                    )
                    .await?;
                    // Native owns the pair's network tracking and current TUN.
                    // Do not add a legacy network RPC after its apply reply.
                    state.applied_physical_network_fingerprint = None;
                    state.domain_resolutions = proposed_state.domain_resolutions;
                    state.working_policy_hash = Some(policy.policy_hash.clone());
                    clear_policy_failure(state);
                    self.clear_split_tunnel_warning(SplitTunnelWarningKind::Operation)
                        .await;
                    self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
                        .await;
                    (
                        if native_outcome == OwnedRedundantPolicyOutcome::Applied {
                            ConnectedPolicyApplyOutcome::Applied
                        } else {
                            ConnectedPolicyApplyOutcome::AppliedWithoutReconnect
                        },
                        SplitTunnelApplyStatus::Applied,
                    )
                }
                Ok(OwnedRedundantPolicyOutcome::RolledBack) => {
                    // Native rolls back its actual recipe, which may predate Core
                    // bootstrap. Do not attest reconstructed cached options as live.
                    self.publish_owned_policy_state(
                        cancel_epoch,
                        &connection,
                        Phase::Connected,
                        Some(RunningSplitTunnelOptions::default()),
                    )
                    .await?;
                    state.domain_resolutions = previous_state.domain_resolutions;
                    mark_policy_failure(state, policy, now_unix);
                    (
                        ConnectedPolicyApplyOutcome::RolledBack,
                        SplitTunnelApplyStatus::RolledBack,
                    )
                }
                Ok(OwnedRedundantPolicyOutcome::Failed) => {
                    self.publish_owned_policy_state(
                        cancel_epoch,
                        &connection,
                        Phase::Stopping,
                        Some(RunningSplitTunnelOptions::default()),
                    )
                    .await?;
                    state.applied_physical_network_fingerprint = None;
                    mark_policy_failure(state, policy, now_unix);
                    (
                        ConnectedPolicyApplyOutcome::Failed,
                        SplitTunnelApplyStatus::Failed,
                    )
                }
                Err(_) => {
                    // Admission/preparation can fail before any native replacement.
                    // Inspect the real transport instead of treating an intact pair
                    // as a failed rollback or issuing an ordinary Stop/Start.
                    let phase = if matches!(
                        self.tunnel.status().await,
                        Ok(nelomai_client_tunnel::TunnelStatus::Running)
                    ) {
                        Phase::Connected
                    } else {
                        Phase::Stopping
                    };
                    self.publish_owned_policy_state(cancel_epoch, &connection, phase, None)
                        .await?;
                    mark_policy_failure(state, policy, now_unix);
                    (
                        ConnectedPolicyApplyOutcome::ApplyFailed,
                        SplitTunnelApplyStatus::Failed,
                    )
                }
            };
            if let Some(code) = outcome.error_code() {
                self.set_split_tunnel_warning(SplitTunnelWarningKind::Operation, code)
                    .await;
                self.logger.record(crate::CoreLogEvent {
                    kind: "split_tunnel.apply_failed",
                    operation_id: None,
                    request_id: None,
                    code: Some(code.into()),
                });
            }
            self.report_policy_apply_outcome(
                policy,
                state,
                access_token,
                now_unix,
                status,
                outcome.error_code().map(str::to_owned),
            )
            .await?;
            return Ok(outcome);
        }
        // An independent native owner may have appeared during policy/DNS I/O.
        // The legacy backend must not replace it even with a matching old lease.
        if self.tunnel.owns_redundant_session().await? {
            return Err(CoreError::StartCancelled);
        }
        let Some(configuration) = configuration else {
            const ERROR_CODE: &str = "split_tunnel_saved_connection_unavailable";
            mark_policy_failure(state, policy, now_unix);
            self.set_split_tunnel_warning(SplitTunnelWarningKind::Operation, ERROR_CODE)
                .await;
            self.logger.record(crate::CoreLogEvent {
                kind: "split_tunnel.apply_failed",
                operation_id: None,
                request_id: None,
                code: Some(ERROR_CODE.to_string()),
            });
            let result = SplitTunnelApplyResult {
                format_version: policy.format_version,
                revision: policy.revision,
                force_revision: policy.force_revision,
                address_revision: policy.address_revision,
                policy_hash: policy.policy_hash.clone(),
                status: SplitTunnelApplyStatus::Failed,
                error_code: Some(ERROR_CODE.to_string()),
                applied_at: rfc3339(now_unix)?,
            };
            self.report_or_queue_apply_result(access_token, state, result)
                .await;
            return Ok(ConnectedPolicyApplyOutcome::ConfigurationUnavailable);
        };
        self.retire_split_tunnel_confirmation(&connection, cancel_epoch)
            .await?;
        if self.tunnel.stop_for_restart().await.is_err() {
            mark_policy_failure(state, policy, now_unix);
            let phase = match self.tunnel.status().await {
                Ok(
                    nelomai_client_tunnel::TunnelStatus::Stopped
                    | nelomai_client_tunnel::TunnelStatus::Stopping
                    | nelomai_client_tunnel::TunnelStatus::Failed,
                ) => Phase::Stopping,
                Ok(
                    nelomai_client_tunnel::TunnelStatus::Starting
                    | nelomai_client_tunnel::TunnelStatus::Running,
                )
                | Err(_) => Phase::Connected,
            };
            let mut current_state = self.state.lock().await;
            self.ensure_start_not_cancelled(cancel_epoch)?;
            *current_state = crate::CoreState {
                phase,
                connection: Some(connection),
            };
            drop(current_state);
            self.set_split_tunnel_warning(
                SplitTunnelWarningKind::Operation,
                "split_tunnel_stop_failed",
            )
            .await;
            let result = SplitTunnelApplyResult {
                format_version: policy.format_version,
                revision: policy.revision,
                force_revision: policy.force_revision,
                address_revision: policy.address_revision,
                policy_hash: policy.policy_hash.clone(),
                status: SplitTunnelApplyStatus::Failed,
                error_code: Some("split_tunnel_stop_failed".to_string()),
                applied_at: rfc3339(now_unix)?,
            };
            if self.split_tunnel_store.save(state).is_err() {
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Storage,
                    "split_tunnel_state_save_failed",
                )
                .await;
            }
            self.report_or_queue_apply_result(access_token, state, result)
                .await;
            return Ok(ConnectedPolicyApplyOutcome::StopFailed);
        }
        {
            let mut current_state = self.state.lock().await;
            self.ensure_start_not_cancelled(cancel_epoch)?;
            current_state.phase = Phase::Connecting;
        }
        let start_new = self
            .tunnel
            .start_for_restart(nelomai_client_tunnel::TunnelStartRequest {
                configuration: nelomai_client_tunnel::TunnelConfiguration::new(
                    configuration.clone(),
                ),
                options: new_options.clone(),
                quick_reconnect: nelomai_client_tunnel::QuickReconnect::Disabled,
                quick_connection: Some(local_restart_connection(&connection)),
                redundancy: None,
            })
            .await;
        // Both success and error can follow a physical start. Never dispatch
        // rollback with a stale epoch; compensate an already dispatched start.
        self.ensure_offline_start_current(cancel_epoch).await?;
        let (outcome, status, error_code) = if start_new.is_ok() {
            *self.split_tunnel_options.lock().await = RunningSplitTunnelOptions::confirmed(
                new_options.clone(),
                &connection.lease_id,
                cancel_epoch,
            );
            state.applied_physical_network_fingerprint = self
                .initialize_physical_network_detector(&new_options)
                .await;
            state.domain_resolutions = proposed_state.domain_resolutions;
            state.working_policy_hash = Some(policy.policy_hash.clone());
            clear_policy_failure(state);
            self.clear_split_tunnel_warning(SplitTunnelWarningKind::Operation)
                .await;
            self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
                .await;
            self.publish_local_start_state(cancel_epoch, Phase::Connected, connection)
                .await?;
            (
                ConnectedPolicyApplyOutcome::Applied,
                SplitTunnelApplyStatus::Applied,
                None,
            )
        } else {
            self.ensure_start_not_cancelled(cancel_epoch)?;
            let rollback = self
                .tunnel
                .start_for_restart(nelomai_client_tunnel::TunnelStartRequest {
                    configuration: nelomai_client_tunnel::TunnelConfiguration::new(configuration),
                    options: previous_options.clone(),
                    quick_reconnect: nelomai_client_tunnel::QuickReconnect::Disabled,
                    quick_connection: Some(local_restart_connection(&connection)),
                    redundancy: None,
                })
                .await;
            self.ensure_offline_start_current(cancel_epoch).await?;
            if rollback.is_ok() {
                state.domain_resolutions = previous_state.domain_resolutions;
                mark_policy_failure(state, policy, now_unix);
                *self.split_tunnel_options.lock().await = RunningSplitTunnelOptions::confirmed(
                    previous_options.clone(),
                    &connection.lease_id,
                    cancel_epoch,
                );
                state.applied_physical_network_fingerprint = self
                    .initialize_physical_network_detector(&previous_options)
                    .await;
                self.publish_local_start_state(cancel_epoch, Phase::Connected, connection)
                    .await?;
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Operation,
                    "split_tunnel_apply_failed",
                )
                .await;
                (
                    ConnectedPolicyApplyOutcome::RolledBack,
                    SplitTunnelApplyStatus::RolledBack,
                    Some("split_tunnel_apply_failed".to_string()),
                )
            } else {
                mark_policy_failure(state, policy, now_unix);
                *self.split_tunnel_options.lock().await = RunningSplitTunnelOptions::default();
                self.physical_network_change.lock().await.reset();
                state.applied_physical_network_fingerprint = None;
                self.publish_local_start_state(cancel_epoch, Phase::Stopping, connection)
                    .await?;
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Operation,
                    "split_tunnel_rollback_failed",
                )
                .await;
                (
                    ConnectedPolicyApplyOutcome::Failed,
                    SplitTunnelApplyStatus::Failed,
                    Some("split_tunnel_rollback_failed".to_string()),
                )
            }
        };
        self.report_policy_apply_outcome(policy, state, access_token, now_unix, status, error_code)
            .await?;
        Ok(outcome)
    }

    async fn publish_owned_policy_state(
        &self,
        cancel_epoch: crate::StartCancellationEpoch,
        connection: &Connection,
        phase: Phase,
        options: Option<RunningSplitTunnelOptions>,
    ) -> Result<(), CoreError> {
        let mut current = self.state.lock().await;
        let mut running = self.split_tunnel_options.lock().await;
        let mut detector = self.physical_network_change.lock().await;
        self.ensure_start_not_cancelled(cancel_epoch)?;
        if !matches!(current.phase, Phase::Connected | Phase::Connecting)
            || !current
                .connection
                .as_ref()
                .is_some_and(|observed| same_local_recovery_execution(observed, connection))
        {
            return Err(CoreError::StartCancelled);
        }
        // Validate every fence under the same locks before retiring/confirming
        // a recipe or resetting its detector. Rejected replies leave S2 intact.
        if let Some(options) = options {
            *running = options;
            detector.reset();
        }
        current.phase = phase;
        Ok(())
    }

    async fn report_policy_apply_outcome(
        &self,
        policy: &SplitTunnelPolicy,
        state: &mut StoredSplitTunnelState,
        access_token: &mut AccessSnapshot,
        now_unix: i64,
        status: SplitTunnelApplyStatus,
        error_code: Option<String>,
    ) -> Result<(), CoreError> {
        let result = SplitTunnelApplyResult {
            format_version: policy.format_version,
            revision: policy.revision,
            force_revision: policy.force_revision,
            address_revision: policy.address_revision,
            policy_hash: policy.policy_hash.clone(),
            status,
            error_code,
            applied_at: rfc3339(now_unix)?,
        };
        if self.split_tunnel_store.save(state).is_err() {
            self.set_split_tunnel_warning(
                SplitTunnelWarningKind::Storage,
                "split_tunnel_state_save_failed",
            )
            .await;
        } else {
            self.clear_split_tunnel_warning(SplitTunnelWarningKind::Storage)
                .await;
        }
        self.report_or_queue_apply_result(access_token, state, result)
            .await;
        Ok(())
    }

    async fn request_split_tunnel_revision(
        &self,
        access_token: &mut AccessSnapshot,
    ) -> Result<SplitTunnelRevision, CoreError> {
        match self.api.split_tunnel_revision(access_token).await {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) => {
                *access_token = self.refresh_access_token(access_token).await?;
                self.api
                    .split_tunnel_revision(access_token)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) async fn restore_running_split_tunnel_options(
        &self,
        connection: &nelomai_contracts::Connection,
        cancel_epoch: crate::StartCancellationEpoch,
    ) {
        {
            let current_state = self.state.lock().await;
            if self.ensure_start_not_cancelled(cancel_epoch).is_err()
                || current_state.phase != crate::Phase::Connected
                || current_state.connection.as_ref() != Some(connection)
            {
                return;
            }
            let mut running = self.split_tunnel_options.lock().await;
            if self.ensure_start_not_cancelled(cancel_epoch).is_err() {
                return;
            }
            if running.is_confirmed_for(&connection.lease_id, cancel_epoch) {
                // Repeated bootstrap must not replace a confirmed live plan
                // with a reconstruction from mutable persistent state.
                return;
            }
            // Unattested options may belong to a retired lease/epoch. Clear
            // them before reconstruction so failure cannot reuse that plan.
            *running = RunningSplitTunnelOptions::default();
        }
        let Ok(state) = self.split_tunnel_store.load() else {
            return;
        };
        let restored_is_confirmed = matches!(self.tunnel.capabilities().await,
            Ok(capabilities) if capabilities.platform != TunnelPlatform::Android);
        let options = match working_policy(&state) {
            Some(policy) => {
                self.effective_tunnel_options(
                    policy,
                    connection.layer,
                    connection.route_mode,
                    OffsetDateTime::now_utc().unix_timestamp(),
                    false,
                )
                .await
            }
            None => self.fallback_tunnel_options().await,
        };
        if let Ok(options) = options {
            let current_state = self.state.lock().await;
            if self.ensure_start_not_cancelled(cancel_epoch).is_err()
                || current_state.phase != crate::Phase::Connected
                || current_state.connection.as_ref() != Some(connection)
            {
                return;
            }
            {
                let mut current = self.split_tunnel_options.lock().await;
                if self.ensure_start_not_cancelled(cancel_epoch).is_err() {
                    return;
                }
                if current.is_confirmed_for(&connection.lease_id, cancel_epoch) {
                    return;
                }
                *current = if restored_is_confirmed {
                    RunningSplitTunnelOptions::confirmed(
                        options.clone(),
                        &connection.lease_id,
                        cancel_epoch,
                    )
                } else {
                    RunningSplitTunnelOptions {
                        options: options.clone(),
                        available_to: Some((connection.lease_id.clone(), cancel_epoch)),
                        native_confirmed: false,
                    }
                };
            }
            if options.policy_hash.is_none() && options.exclude_local_networks {
                self.set_split_tunnel_warning(
                    SplitTunnelWarningKind::Operation,
                    "split_tunnel_local_only",
                )
                .await;
            }
            let mut detector = self.physical_network_change.lock().await;
            if self.ensure_start_not_cancelled(cancel_epoch).is_err() {
                return;
            }
            detector.reset();
            if physical_network_tracking_active(&options) {
                if let Some(fingerprint) = state.applied_physical_network_fingerprint {
                    detector.mark_applied(fingerprint);
                } else {
                    detector.require_revalidation();
                }
            }
        }
    }

    async fn request_split_tunnel_policy(
        &self,
        access_token: &mut AccessSnapshot,
    ) -> Result<SplitTunnelPolicy, CoreError> {
        match self.api.split_tunnel_policy(access_token).await {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) => {
                *access_token = self.refresh_access_token(access_token).await?;
                self.api
                    .split_tunnel_policy(access_token)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn request_split_tunnel_settings(
        &self,
        access_token: &mut AccessSnapshot,
        request: &SplitTunnelSettingsUpdate,
    ) -> Result<SplitTunnelPolicy, CoreError> {
        match self
            .api
            .update_split_tunnel_settings(access_token, request)
            .await
        {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) => {
                *access_token = self.refresh_access_token(access_token).await?;
                self.api
                    .update_split_tunnel_settings(access_token, request)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn request_add_split_tunnel_address_rule(
        &self,
        access_token: &mut AccessSnapshot,
        request: &SplitTunnelAddressRuleUpdate,
    ) -> Result<SplitTunnelPolicy, CoreError> {
        match self
            .api
            .add_split_tunnel_address_rule(access_token, request)
            .await
        {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) => {
                *access_token = self.refresh_access_token(access_token).await?;
                self.api
                    .add_split_tunnel_address_rule(access_token, request)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn request_remove_split_tunnel_address_rule(
        &self,
        access_token: &mut AccessSnapshot,
        rule_id: i64,
        scope: SplitTunnelAddressRuleScope,
    ) -> Result<SplitTunnelPolicy, CoreError> {
        match self
            .api
            .remove_split_tunnel_address_rule(access_token, rule_id, scope)
            .await
        {
            Ok(response) => Ok(response),
            Err(CoreApiError::Unauthorized) => {
                *access_token = self.refresh_access_token(access_token).await?;
                self.api
                    .remove_split_tunnel_address_rule(access_token, rule_id, scope)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn send_apply_result(
        &self,
        access_token: &mut AccessSnapshot,
        result: &SplitTunnelApplyResult,
    ) -> Result<(), CoreError> {
        match self
            .api
            .report_split_tunnel_apply_result(access_token, result)
            .await
        {
            Ok(()) => Ok(()),
            Err(CoreApiError::Unauthorized) => {
                *access_token = self.refresh_access_token(access_token).await?;
                self.api
                    .report_split_tunnel_apply_result(access_token, result)
                    .await
                    .map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn flush_pending_apply_results(
        &self,
        access_token: &mut AccessSnapshot,
        state: &mut StoredSplitTunnelState,
    ) {
        let pending = std::mem::take(&mut state.pending_apply_results);
        for result in pending {
            if self.send_apply_result(access_token, &result).await.is_err() {
                state.pending_apply_results.push(result);
            }
        }
    }

    async fn report_or_queue_apply_result(
        &self,
        access_token: &mut AccessSnapshot,
        state: &mut StoredSplitTunnelState,
        result: SplitTunnelApplyResult,
    ) {
        if self.send_apply_result(access_token, &result).await.is_err() {
            state.pending_apply_results.push(result);
        }
    }
}

fn physical_network_tracking_active(options: &TunnelOptions) -> bool {
    options.policy_hash.is_some()
        && (options.exclude_local_networks || !options.excluded_ipv4_cidrs.is_empty())
}

fn policy_retry_due(
    state: &StoredSplitTunnelState,
    policy: &SplitTunnelPolicy,
    now_unix: i64,
) -> bool {
    state.failed_policy_hash.as_deref() != Some(policy.policy_hash.as_str())
        || state
            .failed_policy_retry_after_unix
            .is_none_or(|retry_after| now_unix >= retry_after)
}

fn mark_policy_failure(
    state: &mut StoredSplitTunnelState,
    policy: &SplitTunnelPolicy,
    now_unix: i64,
) {
    state.failed_policy_hash = Some(policy.policy_hash.clone());
    state.failed_policy_retry_after_unix =
        Some(now_unix.saturating_add(FAILED_POLICY_RETRY_SECONDS));
}

fn clear_policy_failure(state: &mut StoredSplitTunnelState) {
    state.failed_policy_hash = None;
    state.failed_policy_retry_after_unix = None;
}

fn clear_stale_policy_failure(state: &mut StoredSplitTunnelState, policy: &SplitTunnelPolicy) {
    if state.failed_policy_hash.as_deref() != Some(policy.policy_hash.as_str()) {
        clear_policy_failure(state);
    }
}

fn remember_previous_working_policy(state: &mut StoredSplitTunnelState) {
    if state
        .cached_policy
        .as_ref()
        .zip(state.working_policy_hash.as_ref())
        .is_some_and(|(policy, hash)| &policy.policy_hash == hash)
    {
        state.previous_working_policy = state.cached_policy.clone();
    }
}

fn working_policy(state: &StoredSplitTunnelState) -> Option<&SplitTunnelPolicy> {
    let working_hash = state.working_policy_hash.as_deref()?;
    state
        .cached_policy
        .as_ref()
        .into_iter()
        .chain(state.previous_working_policy.as_ref())
        .find(|policy| policy.policy_hash == working_hash)
}

fn rfc3339(unix_timestamp: i64) -> Result<String, CoreError> {
    OffsetDateTime::from_unix_timestamp(unix_timestamp)
        .map_err(|_| CoreError::SplitTunnel("split_tunnel_invalid_clock".to_string()))?
        .format(&Rfc3339)
        .map_err(|_| CoreError::SplitTunnel("split_tunnel_invalid_clock".to_string()))
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

struct InstalledPackageIndex<'a> {
    exact: HashMap<&'a str, &'a SplitTunnelSelectedPackage>,
    folded: HashMap<String, Option<&'a SplitTunnelSelectedPackage>>,
}

impl<'a> InstalledPackageIndex<'a> {
    fn new(installed: &'a [SplitTunnelSelectedPackage]) -> Self {
        let exact = installed
            .iter()
            .map(|package| (package.package_id.as_str(), package))
            .collect();
        let mut folded = HashMap::new();
        for package in installed {
            let key = package.package_id.to_ascii_lowercase();
            folded
                .entry(key)
                .and_modify(|entry| *entry = None)
                .or_insert(Some(package));
        }
        Self { exact, folded }
    }

    fn resolve(&self, package_id: &str) -> Option<&'a SplitTunnelSelectedPackage> {
        self.exact.get(package_id).copied().or_else(|| {
            self.folded
                .get(&package_id.to_ascii_lowercase())
                .copied()
                .flatten()
        })
    }
}

fn canonical_available_packages(
    package_ids: &[String],
    installed: &InstalledPackageIndex<'_>,
) -> Vec<String> {
    package_ids
        .iter()
        .filter_map(|package_id| installed.resolve(package_id))
        .map(|package| package.package_id.clone())
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

#[cfg(test)]
mod domain_resolution_tests {
    use super::*;
    use nelomai_contracts::{SplitTunnelAddressRule, SplitTunnelAddressRuleScope};
    use std::sync::{Arc, Mutex};

    fn domain_policy(domains: &[&str]) -> SplitTunnelPolicy {
        SplitTunnelPolicy {
            format_version: ADDRESS_RULE_FORMAT_VERSION,
            enabled: true,
            revision: 1,
            force_revision: 0,
            address_revision: 1,
            policy_hash: format!("sha256:{}", "a".repeat(64)),
            mode: SplitTunnelMode::ExcludeSelected,
            exclude_local_networks: true,
            mandatory_excluded_packages: Vec::new(),
            suggested_name_fragments: Vec::new(),
            selected_packages: Vec::new(),
            excluded_ipv4_cidrs: Vec::new(),
            address_rules: domains
                .iter()
                .enumerate()
                .map(|(index, domain)| SplitTunnelAddressRule {
                    id: index as i64 + 1,
                    scope: SplitTunnelAddressRuleScope::ThisDevice,
                    kind: SplitTunnelAddressRuleKind::Domain,
                    value: (*domain).to_string(),
                })
                .collect(),
            generated_at: "2026-07-31T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn http_urls_are_reduced_to_their_host_before_the_panel_request() {
        assert_eq!(
            normalize_address_rule_input(" https://Example.COM:8443/catalog/item?q=1#details ")
                .unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_address_rule_input("http://203.0.113.25/status").unwrap(),
            "203.0.113.25"
        );
    }

    #[test]
    fn unsupported_or_malformed_urls_are_rejected_locally() {
        for value in [
            "ftp://example.com/archive",
            "file:///etc/hosts",
            "https://example.com:invalid/path",
        ] {
            assert_eq!(
                normalize_address_rule_input(value),
                Err(SplitTunnelPolicyError::InvalidAddressRule)
            );
        }
    }

    #[tokio::test]
    async fn failed_refresh_keeps_last_good_domain_addresses() {
        let mut state = StoredSplitTunnelState {
            domain_resolutions: vec![StoredSplitTunnelDomainResolution {
                domain: "cached.example".to_string(),
                ipv4_cidrs: vec!["198.51.100.10/32".to_string()],
                resolved_at_unix: 100,
            }],
            ..StoredSplitTunnelState::default()
        };
        let requested = Arc::new(Mutex::new(Vec::new()));
        let resolver = {
            let requested = requested.clone();
            move |domain: String| {
                let requested = requested.clone();
                async move {
                    requested.lock().unwrap().push(domain.clone());
                    (domain == "fresh.example").then(|| vec!["203.0.113.8/32".to_string()])
                }
            }
        };

        let outcome = resolve_policy_domains_with(
            &domain_policy(&["cached.example", "fresh.example"]),
            &mut state,
            200,
            DomainResolutionMode::Refresh,
            resolver,
        )
        .await;

        assert!(outcome.had_failures);
        assert!(!outcome.missing_cache);
        assert_eq!(outcome.ipv4_cidrs, ["198.51.100.10/32", "203.0.113.8/32"]);
        assert_eq!(requested.lock().unwrap().len(), 2);
        assert_eq!(state.domain_resolutions.len(), 2);
        assert_eq!(
            state
                .domain_resolutions
                .iter()
                .find(|item| item.domain == "cached.example")
                .unwrap()
                .resolved_at_unix,
            100
        );
    }

    #[tokio::test]
    async fn cached_domains_skip_lookup_until_a_refresh_is_requested() {
        let mut state = StoredSplitTunnelState {
            domain_resolutions: vec![StoredSplitTunnelDomainResolution {
                domain: "cached.example".to_string(),
                ipv4_cidrs: vec!["198.51.100.10/32".to_string()],
                resolved_at_unix: 100,
            }],
            ..StoredSplitTunnelState::default()
        };
        let calls = Arc::new(Mutex::new(0usize));
        let resolver = {
            let calls = calls.clone();
            move |_domain: String| {
                let calls = calls.clone();
                async move {
                    *calls.lock().unwrap() += 1;
                    None
                }
            }
        };

        let outcome = resolve_policy_domains_with(
            &domain_policy(&["cached.example"]),
            &mut state,
            200,
            DomainResolutionMode::ResolveMissing,
            resolver,
        )
        .await;

        assert!(!outcome.had_failures);
        assert!(!outcome.missing_cache);
        assert_eq!(outcome.ipv4_cidrs, ["198.51.100.10/32"]);
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn cache_only_reports_missing_domains_without_invoking_the_resolver() {
        let mut state = StoredSplitTunnelState {
            domain_resolutions: vec![StoredSplitTunnelDomainResolution {
                domain: "cached.example".into(),
                ipv4_cidrs: vec!["198.51.100.10/32".into()],
                resolved_at_unix: 100,
            }],
            ..StoredSplitTunnelState::default()
        };
        let outcome = resolve_policy_domains_with(
            &domain_policy(&["cached.example", "missing.example"]),
            &mut state,
            200,
            DomainResolutionMode::CachedOnly,
            |_domain| async { panic!("cache-only mode must not call DNS even on a cache miss") },
        )
        .await;
        assert!(outcome.missing_cache);
        assert!(!outcome.had_failures);
        assert_eq!(outcome.ipv4_cidrs, ["198.51.100.10/32"]);
        assert_eq!(state.domain_resolutions.len(), 1);
        assert_eq!(state.domain_resolutions[0].resolved_at_unix, 100);
    }

    #[tokio::test]
    async fn first_resolution_failure_does_not_silently_drop_a_domain() {
        let mut state = StoredSplitTunnelState::default();
        let outcome = resolve_policy_domains_with(
            &domain_policy(&["missing.example"]),
            &mut state,
            200,
            DomainResolutionMode::Refresh,
            |_domain| async { None },
        )
        .await;

        assert!(outcome.had_failures);
        assert!(outcome.missing_cache);
        assert!(outcome.ipv4_cidrs.is_empty());
    }
}

#[cfg(test)]
mod physical_network_tests {
    use super::*;

    #[test]
    fn network_change_requires_two_matching_observations() {
        let mut detector = PhysicalNetworkChangeDetector::default();

        assert_eq!(
            detector.observe("network-a".to_string(), 1_000),
            PhysicalNetworkObservation::BaselineRecorded
        );
        assert_eq!(
            detector.observe("network-b".to_string(), 1_030),
            PhysicalNetworkObservation::ChangePending
        );
        assert_eq!(
            detector.observe("network-a".to_string(), 1_060),
            PhysicalNetworkObservation::Unchanged
        );
        assert_eq!(
            detector.observe("network-b".to_string(), 1_090),
            PhysicalNetworkObservation::ChangePending
        );
        assert_eq!(
            detector.observe("network-b".to_string(), 1_120),
            PhysicalNetworkObservation::ConfirmedChange("network-b".to_string())
        );
        detector.mark_applied("network-b".to_string());
        assert_eq!(
            detector.observe("network-b".to_string(), 1_150),
            PhysicalNetworkObservation::Unchanged
        );
    }

    #[test]
    fn reset_requires_a_new_baseline() {
        let mut detector = PhysicalNetworkChangeDetector::default();
        detector.observe("network-a".to_string(), 1_000);
        detector.observe("network-b".to_string(), 1_030);
        detector.reset();

        assert_eq!(
            detector.observe("network-b".to_string(), 1_060),
            PhysicalNetworkObservation::BaselineRecorded
        );
    }

    #[test]
    fn repeated_probe_failures_are_reported_once_until_a_success() {
        let mut detector = PhysicalNetworkChangeDetector::default();

        assert!(detector.mark_probe_failed(false));
        assert!(!detector.mark_probe_failed(false));
        detector.observe("network-a".to_string(), 1_000);
        assert!(detector.mark_probe_failed(false));
    }

    #[test]
    fn successful_probe_after_failure_reconnects_even_when_network_is_unchanged() {
        let mut detector = PhysicalNetworkChangeDetector::default();
        detector.observe("network-a".to_string(), 1_000);
        assert!(detector.mark_probe_failed(true));

        assert_eq!(
            detector.observe("network-a".to_string(), 1_030),
            PhysicalNetworkObservation::ConfirmedChange("network-a".to_string())
        );
        detector.defer_retry(1_030);
        assert_eq!(
            detector.observe("network-a".to_string(), 1_329),
            PhysicalNetworkObservation::RetryDeferred
        );
        assert_eq!(
            detector.observe("network-a".to_string(), 1_330),
            PhysicalNetworkObservation::ConfirmedChange("network-a".to_string())
        );
    }

    #[test]
    fn transient_probe_failure_keeps_an_unchanged_network_connected() {
        let mut detector = PhysicalNetworkChangeDetector::default();
        detector.observe("network-a".to_string(), 1_000);
        assert!(detector.mark_probe_failed(false));

        assert_eq!(
            detector.observe("network-a".to_string(), 1_030),
            PhysicalNetworkObservation::Unchanged
        );
    }

    #[test]
    fn only_physical_egress_loss_requires_reconnect_after_probe_recovery() {
        assert!(probe_failure_requires_reconnect(
            &nelomai_client_tunnel::TunnelError::Backend("physical_egress_unavailable".to_string(),)
        ));
        assert!(!probe_failure_requires_reconnect(
            &nelomai_client_tunnel::TunnelError::Backend("tunnel_service_timeout".to_string())
        ));
        assert!(!probe_failure_requires_reconnect(
            &nelomai_client_tunnel::TunnelError::InvalidOptions {
                code: "invalid_options",
            }
        ));
    }

    #[test]
    fn restored_detector_requires_confirmation_when_no_baseline_was_persisted() {
        let mut detector = PhysicalNetworkChangeDetector::default();
        detector.require_revalidation();

        assert_eq!(
            detector.observe("network-a".to_string(), 1_000),
            PhysicalNetworkObservation::ChangePending
        );
        assert_eq!(
            detector.observe("network-a".to_string(), 1_030),
            PhysicalNetworkObservation::ConfirmedChange("network-a".to_string())
        );
    }

    #[test]
    fn failed_reconnect_is_deferred_without_forgetting_the_network_change() {
        let mut detector = PhysicalNetworkChangeDetector::default();
        detector.observe("network-a".to_string(), 1_000);
        detector.observe("network-b".to_string(), 1_030);
        assert!(matches!(
            detector.observe("network-b".to_string(), 1_060),
            PhysicalNetworkObservation::ConfirmedChange(_)
        ));
        detector.defer_retry(1_060);

        assert_eq!(
            detector.observe("network-b".to_string(), 1_359),
            PhysicalNetworkObservation::RetryDeferred
        );
        assert!(matches!(
            detector.observe("network-b".to_string(), 1_360),
            PhysicalNetworkObservation::ConfirmedChange(_)
        ));
    }
}
