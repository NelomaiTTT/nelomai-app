//! Nonsecret cleanup handoff metadata. Tunnel configurations and every form of
//! credential are intentionally absent from this type.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupEngineRoleV1 {
    Primary,
    Redundant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupOperationV1 {
    pub operation_id: String,
    pub request_fingerprint: String,
    pub contract_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupEnvelopeV1 {
    pub cleanup_contract_version: u32,
    pub lease_ids: Vec<String>,
    pub redundant_session_ids: Vec<String>,
    pub operations: Vec<CleanupOperationV1>,
    pub engine_role: CleanupEngineRoleV1,
    pub background_reference: Option<String>,
}

impl CleanupEnvelopeV1 {
    pub(crate) fn validate(&self) -> bool {
        self.cleanup_contract_version == 1
            && valid_unique_ids(&self.lease_ids)
            && valid_unique_ids(&self.redundant_session_ids)
            && self.operations.len() <= 1024
            && self.operations.iter().all(|operation| {
                valid_id(&operation.operation_id)
                    && valid_fingerprint(&operation.request_fingerprint)
                    && operation.contract_version > 0
                    && operation.contract_version <= i32::MAX as u32
            })
            && self
                .operations
                .iter()
                .map(|operation| operation.operation_id.as_str())
                .collect::<HashSet<_>>()
                .len()
                == self.operations.len()
            && self.background_reference.as_deref().is_none_or(valid_id)
    }
}

fn valid_unique_ids(values: &[String]) -> bool {
    values.len() <= 1024
        && values.iter().all(|value| valid_id(value))
        && values
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>()
            .len()
            == values.len()
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

pub(crate) fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
