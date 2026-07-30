use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelMode {
    ExcludeSelected,
    IncludeSelected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelRevision {
    pub enabled: bool,
    pub revision: i64,
    pub force_revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelSelectedPackage {
    pub package_id: String,
    pub display_name: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelPolicy {
    pub format_version: u16,
    pub enabled: bool,
    pub revision: i64,
    pub force_revision: i64,
    pub policy_hash: String,
    pub mode: SplitTunnelMode,
    pub exclude_local_networks: bool,
    pub mandatory_excluded_packages: Vec<String>,
    pub suggested_name_fragments: Vec<String>,
    pub selected_packages: Vec<String>,
    pub excluded_ipv4_cidrs: Vec<String>,
    pub generated_at: String,
}

impl SplitTunnelPolicy {
    pub fn validate_timestamps(&self) -> Result<(), SplitTunnelTimestampError> {
        validate_rfc3339(&self.generated_at, SplitTunnelTimestampField::GeneratedAt)
    }
}

impl fmt::Debug for SplitTunnelPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SplitTunnelPolicy")
            .field("format_version", &self.format_version)
            .field("enabled", &self.enabled)
            .field("revision", &self.revision)
            .field("force_revision", &self.force_revision)
            .field("policy_hash", &self.policy_hash)
            .field("mode", &self.mode)
            .field("exclude_local_networks", &self.exclude_local_networks)
            .field(
                "mandatory_excluded_packages_count",
                &self.mandatory_excluded_packages.len(),
            )
            .field(
                "suggested_name_fragments_count",
                &self.suggested_name_fragments.len(),
            )
            .field("selected_packages_count", &self.selected_packages.len())
            .field("excluded_ipv4_cidrs_count", &self.excluded_ipv4_cidrs.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelSettingsUpdate {
    pub mode: SplitTunnelMode,
    pub exclude_local_networks: bool,
    pub selected_packages: Vec<SplitTunnelSelectedPackage>,
}

impl fmt::Debug for SplitTunnelSettingsUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SplitTunnelSettingsUpdate")
            .field("mode", &self.mode)
            .field("exclude_local_networks", &self.exclude_local_networks)
            .field("selected_packages_count", &self.selected_packages.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelApplyStatus {
    Applied,
    RolledBack,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelApplyResult {
    pub format_version: u16,
    pub revision: i64,
    pub force_revision: i64,
    pub policy_hash: String,
    pub status: SplitTunnelApplyStatus,
    pub error_code: Option<String>,
    pub applied_at: String,
}

impl SplitTunnelApplyResult {
    pub fn validate_timestamps(&self) -> Result<(), SplitTunnelTimestampError> {
        validate_rfc3339(&self.applied_at, SplitTunnelTimestampField::AppliedAt)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitTunnelTimestampField {
    GeneratedAt,
    AppliedAt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitTunnelTimestampError {
    pub field: SplitTunnelTimestampField,
}

impl fmt::Display for SplitTunnelTimestampError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field = match self.field {
            SplitTunnelTimestampField::GeneratedAt => "generated_at",
            SplitTunnelTimestampField::AppliedAt => "applied_at",
        };
        write!(formatter, "{field} must be an RFC 3339 timestamp")
    }
}

impl Error for SplitTunnelTimestampError {}

fn validate_rfc3339(
    value: &str,
    field: SplitTunnelTimestampField,
) -> Result<(), SplitTunnelTimestampError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| SplitTunnelTimestampError { field })
}
