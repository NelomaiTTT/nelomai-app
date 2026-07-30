use crate::{ClientCore, CoreApi, CoreApiError, CoreError, CoreLogger, Phase};
use nelomai_client_storage::{SecretStore, StoredSplitTunnelState};
use nelomai_client_tunnel::{TunnelCapabilities, TunnelOptions, TunnelPlatform};
use nelomai_contracts::{
    Layer, RouteMode, SplitTunnelApplyResult, SplitTunnelApplyStatus, SplitTunnelMode,
    SplitTunnelPolicy, SplitTunnelRevision, SplitTunnelSelectedPackage, SplitTunnelSettingsUpdate,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const SUPPORTED_FORMAT_VERSION: u16 = 1;
const MAX_MANDATORY_PACKAGES: usize = 512;
const MAX_SUGGESTIONS: usize = 128;
const MAX_SELECTED_PACKAGES: usize = 512;
const MAX_IPV4_CIDRS: usize = 16_384;
const REVISION_POLL_SECONDS: i64 = 5 * 60;
const FULL_SYNC_SECONDS: i64 = 24 * 60 * 60;

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

pub fn validate_split_tunnel_policy(
    policy: &SplitTunnelPolicy,
) -> Result<(), SplitTunnelPolicyError> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitTunnelSyncOutcome {
    Skipped,
    Unchanged,
    Updated { reconnected: bool },
    CachedOffline,
    UnsupportedPolicy,
}

impl<A, S, T, L> ClientCore<A, S, T, L>
where
    A: CoreApi,
    S: SecretStore,
    T: nelomai_client_tunnel::TunnelController,
    L: CoreLogger,
{
    pub fn set_split_tunnel_installed_packages(&self, packages: Vec<SplitTunnelSelectedPackage>) {
        if let Ok(mut stored) = self.split_tunnel_packages.write() {
            *stored = packages;
        }
    }

    pub async fn split_tunnel_warning(&self) -> Option<String> {
        self.split_tunnel_warning.lock().await.clone()
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

        let mut access_token = self.load_auth()?.access_token.ok_or(CoreError::SignedOut)?;
        self.flush_pending_apply_results(&mut access_token, &mut state)
            .await;
        let revision = match self.request_split_tunnel_revision(&mut access_token).await {
            Ok(revision) => revision,
            Err(CoreError::Api(CoreApiError::Retryable)) => {
                state.last_revision_check_unix = Some(now_unix);
                self.split_tunnel_store
                    .save(&state)
                    .map_err(|_| CoreError::Storage)?;
                *self.split_tunnel_warning.lock().await =
                    Some("split_tunnel_cached_offline".to_string());
                return Ok(SplitTunnelSyncOutcome::CachedOffline);
            }
            Err(error) => return Err(error),
        };

        let force_revision_changed = revision.force_revision > state.last_seen_force_revision;
        let full_sync_due = force_full
            || state.cached_policy.is_none()
            || state
                .last_full_sync_unix
                .is_none_or(|last| now_unix.saturating_sub(last) >= FULL_SYNC_SECONDS)
            || state.cached_policy.as_ref().is_some_and(|policy| {
                policy.revision != revision.revision || policy.enabled != revision.enabled
            })
            || force_revision_changed;
        state.last_revision_check_unix = Some(now_unix);
        state.last_seen_force_revision = revision.force_revision;
        if !full_sync_due {
            let needs_retry = self.connected_connection().await.is_some()
                && state.cached_policy.as_ref().is_some_and(|policy| {
                    state.working_policy_hash.as_deref() != Some(policy.policy_hash.as_str())
                });
            if let Some(policy) = needs_retry.then(|| state.cached_policy.clone()).flatten() {
                *self.split_tunnel_warning.lock().await = None;
                let reconnected = self
                    .apply_policy_if_connected(&policy, &mut state, &mut access_token, now_unix)
                    .await?;
                self.split_tunnel_store
                    .save(&state)
                    .map_err(|_| CoreError::Storage)?;
                return Ok(SplitTunnelSyncOutcome::Updated { reconnected });
            }
            self.split_tunnel_store
                .save(&state)
                .map_err(|_| CoreError::Storage)?;
            *self.split_tunnel_warning.lock().await = None;
            return Ok(SplitTunnelSyncOutcome::Unchanged);
        }

        let policy = match self.request_split_tunnel_policy(&mut access_token).await {
            Ok(policy) => policy,
            Err(CoreError::Api(CoreApiError::Retryable)) => {
                self.split_tunnel_store
                    .save(&state)
                    .map_err(|_| CoreError::Storage)?;
                *self.split_tunnel_warning.lock().await =
                    Some("split_tunnel_cached_offline".to_string());
                return Ok(SplitTunnelSyncOutcome::CachedOffline);
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = validate_split_tunnel_policy(&policy) {
            self.split_tunnel_store
                .save(&state)
                .map_err(|_| CoreError::Storage)?;
            *self.split_tunnel_warning.lock().await = Some(error.stable_code().to_string());
            return Ok(SplitTunnelSyncOutcome::UnsupportedPolicy);
        }

        let changed = state
            .cached_policy
            .as_ref()
            .is_none_or(|cached| cached.policy_hash != policy.policy_hash);
        remember_previous_working_policy(&mut state);
        state.cached_policy = Some(policy.clone());
        state.last_full_sync_unix = Some(now_unix);
        self.split_tunnel_store
            .save(&state)
            .map_err(|_| CoreError::Storage)?;
        *self.split_tunnel_warning.lock().await = None;
        let needs_apply =
            changed || state.working_policy_hash.as_deref() != Some(policy.policy_hash.as_str());
        let reconnected = if needs_apply {
            self.apply_policy_if_connected(&policy, &mut state, &mut access_token, now_unix)
                .await?
        } else {
            false
        };
        self.split_tunnel_store
            .save(&state)
            .map_err(|_| CoreError::Storage)?;
        Ok(SplitTunnelSyncOutcome::Updated { reconnected })
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
        let mut access_token = self.load_auth()?.access_token.ok_or(CoreError::SignedOut)?;
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
        state.cached_policy = Some(policy.clone());
        state.last_full_sync_unix = Some(now_unix);
        state.last_revision_check_unix = Some(now_unix);
        state.last_seen_force_revision = policy.force_revision;
        self.split_tunnel_store
            .save(&state)
            .map_err(|_| CoreError::Storage)?;
        *self.split_tunnel_warning.lock().await = None;
        let needs_apply =
            changed || state.working_policy_hash.as_deref() != Some(policy.policy_hash.as_str());
        if needs_apply {
            self.apply_policy_if_connected(&policy, &mut state, &mut access_token, now_unix)
                .await?;
        }
        self.split_tunnel_store
            .save(&state)
            .map_err(|_| CoreError::Storage)?;
        Ok(policy)
    }

    pub(crate) async fn effective_tunnel_options(
        &self,
        policy: &SplitTunnelPolicy,
        layer: Layer,
        route_mode: RouteMode,
    ) -> Result<TunnelOptions, CoreError> {
        let capabilities = self.tunnel.capabilities().await?;
        let packages = self
            .split_tunnel_packages
            .read()
            .map(|packages| packages.clone())
            .unwrap_or_default();
        EffectiveSplitTunnelPolicy::build(policy, &packages, capabilities, layer, route_mode)
            .map(|effective| effective.options)
            .map_err(|error| CoreError::SplitTunnel(error.stable_code().to_string()))
    }

    pub(crate) async fn record_started_split_tunnel_policy(
        &self,
        policy: &SplitTunnelPolicy,
        options: TunnelOptions,
        access_token: Option<&mut String>,
        now_unix: i64,
    ) -> Result<(), CoreError> {
        *self.split_tunnel_options.lock().await = options.clone();
        if options.policy_hash.is_none() {
            return Ok(());
        }
        let mut state = self
            .split_tunnel_store
            .load()
            .map_err(|_| CoreError::Storage)?;
        remember_previous_working_policy(&mut state);
        state.working_policy_hash = Some(policy.policy_hash.clone());
        let result = SplitTunnelApplyResult {
            format_version: SUPPORTED_FORMAT_VERSION,
            revision: policy.revision,
            force_revision: policy.force_revision,
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
        let Ok(stored) = self.load_auth() else {
            return;
        };
        let Some(mut access_token) = stored.access_token else {
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
        access_token: &mut String,
        now_unix: i64,
    ) -> Result<bool, CoreError> {
        let _connection_guard = self.connection_gate.lock().await;
        let current = {
            let current_state = self.state.lock().await;
            (current_state.phase == Phase::Connected)
                .then(|| current_state.connection.clone())
                .flatten()
        };
        let Some(connection) = current else {
            return Ok(false);
        };
        let stored = self.load_auth()?;
        let configuration = stored
            .saved_connection
            .as_ref()
            .into_iter()
            .chain(stored.pinned_connection.as_ref())
            .find(|saved| saved.lease_id == connection.lease_id)
            .map(|saved| saved.configuration.clone())
            .ok_or(CoreError::SavedConnectionUnavailable)?;
        let new_options = match self
            .effective_tunnel_options(policy, connection.layer, connection.route_mode)
            .await
        {
            Ok(options) => options,
            Err(CoreError::SplitTunnel(code)) => {
                *self.split_tunnel_warning.lock().await = Some(code);
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let mut previous_options = self.split_tunnel_options.lock().await.clone();
        if previous_options == TunnelOptions::default() {
            if let Some(working_policy) = working_policy(state) {
                previous_options = self
                    .effective_tunnel_options(
                        working_policy,
                        connection.layer,
                        connection.route_mode,
                    )
                    .await
                    .unwrap_or_default();
            }
        }
        if new_options == previous_options {
            return Ok(false);
        }

        self.tunnel.stop().await?;
        self.set_phase(Phase::Connecting).await;
        let start_new = self
            .tunnel
            .start(nelomai_client_tunnel::TunnelStartRequest {
                configuration: nelomai_client_tunnel::TunnelConfiguration::new(
                    configuration.clone(),
                ),
                options: new_options.clone(),
            })
            .await;
        let (status, error_code) = if start_new.is_ok() {
            *self.split_tunnel_options.lock().await = new_options;
            state.working_policy_hash = Some(policy.policy_hash.clone());
            *self.state.lock().await = crate::CoreState {
                phase: Phase::Connected,
                connection: Some(connection),
            };
            (SplitTunnelApplyStatus::Applied, None)
        } else {
            let rollback = self
                .tunnel
                .start(nelomai_client_tunnel::TunnelStartRequest {
                    configuration: nelomai_client_tunnel::TunnelConfiguration::new(configuration),
                    options: previous_options.clone(),
                })
                .await;
            if rollback.is_ok() {
                *self.split_tunnel_options.lock().await = previous_options;
                *self.state.lock().await = crate::CoreState {
                    phase: Phase::Connected,
                    connection: Some(connection),
                };
                (
                    SplitTunnelApplyStatus::RolledBack,
                    Some("split_tunnel_apply_failed".to_string()),
                )
            } else {
                *self.split_tunnel_options.lock().await = TunnelOptions::default();
                *self.state.lock().await = crate::CoreState {
                    phase: Phase::Ready,
                    connection: Some(connection),
                };
                (
                    SplitTunnelApplyStatus::Failed,
                    Some("split_tunnel_rollback_failed".to_string()),
                )
            }
        };
        let result = SplitTunnelApplyResult {
            format_version: SUPPORTED_FORMAT_VERSION,
            revision: policy.revision,
            force_revision: policy.force_revision,
            policy_hash: policy.policy_hash.clone(),
            status,
            error_code,
            applied_at: rfc3339(now_unix)?,
        };
        self.report_or_queue_apply_result(access_token, state, result)
            .await;
        Ok(true)
    }

    async fn request_split_tunnel_revision(
        &self,
        access_token: &mut String,
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
    ) {
        let Ok(state) = self.split_tunnel_store.load() else {
            return;
        };
        let Some(policy) = working_policy(&state) else {
            return;
        };
        if let Ok(options) = self
            .effective_tunnel_options(policy, connection.layer, connection.route_mode)
            .await
        {
            *self.split_tunnel_options.lock().await = options;
        }
    }

    async fn request_split_tunnel_policy(
        &self,
        access_token: &mut String,
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
        access_token: &mut String,
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

    async fn send_apply_result(
        &self,
        access_token: &mut String,
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
        access_token: &mut String,
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
        access_token: &mut String,
        state: &mut StoredSplitTunnelState,
        result: SplitTunnelApplyResult,
    ) {
        if self.send_apply_result(access_token, &result).await.is_err() {
            state.pending_apply_results.push(result);
        }
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
