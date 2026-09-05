//! Nonsecret cleanup handoff metadata. Tunnel configurations and every form of
//! credential are intentionally absent from this type.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const MAX_CLEANUP_ENVELOPE_BYTES: usize = 256 * 1024;

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
    pub provenance: CleanupOperationProvenanceV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provenance", rename_all = "snake_case", deny_unknown_fields)]
pub enum CleanupOperationProvenanceV1 {
    Verified {
        request_fingerprint: String,
        contract_version: u32,
    },
    LegacyUnknown,
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

#[derive(Debug, thiserror::Error)]
pub enum CleanupEnvelopeError {
    #[error("runtime cleanup envelope is invalid")]
    Invalid,
}

impl CleanupEnvelopeV1 {
    pub fn from_runtime_snapshot(
        snapshot: &nelomai_client_storage::RuntimeCleanupSnapshotV1,
        engine_role: CleanupEngineRoleV1,
        background_reference: Option<String>,
    ) -> Result<Self, CleanupEnvelopeError> {
        let mut operations = Vec::new();
        for operation in &snapshot.operations {
            let provenance = match (
                operation.request_fingerprint.as_ref(),
                operation.contract_version,
            ) {
                (Some(request_fingerprint), Some(contract_version)) => {
                    CleanupOperationProvenanceV1::Verified {
                        request_fingerprint: request_fingerprint.clone(),
                        contract_version,
                    }
                }
                (None, None) => CleanupOperationProvenanceV1::LegacyUnknown,
                _ => return Err(CleanupEnvelopeError::Invalid),
            };
            push_operation(&mut operations, &operation.operation_id, provenance);
        }
        let envelope = Self {
            cleanup_contract_version: 1,
            lease_ids: snapshot.lease_ids.clone(),
            redundant_session_ids: Vec::new(),
            operations,
            engine_role,
            background_reference,
        };
        if envelope.validate() {
            Ok(envelope)
        } else {
            Err(CleanupEnvelopeError::Invalid)
        }
    }

    pub fn from_runtime_state(
        state: &nelomai_client_storage::RuntimeStateV1,
        engine_role: CleanupEngineRoleV1,
        background_reference: Option<String>,
    ) -> Result<Self, CleanupEnvelopeError> {
        let mut lease_ids = Vec::new();
        for lease_id in state
            .saved_connection
            .as_ref()
            .map(|connection| connection.lease_id.as_str())
            .into_iter()
            .chain(
                state
                    .pinned_connection
                    .as_ref()
                    .map(|connection| connection.lease_id.as_str()),
            )
            .chain(
                state
                    .pending_stalled_stop
                    .as_ref()
                    .map(|pending| pending.lease_id.as_str()),
            )
            .chain(
                state
                    .pending_compensation_stop
                    .as_ref()
                    .map(|pending| pending.lease_id.as_str()),
            )
        {
            push_unique(&mut lease_ids, lease_id);
        }

        let mut operations = Vec::new();
        if let Some(pending) = &state.pending_start {
            let provenance = match (
                pending.request_fingerprint.as_ref(),
                pending.recovery_contract_version,
            ) {
                (Some(request_fingerprint), Some(contract_version)) => {
                    CleanupOperationProvenanceV1::Verified {
                        request_fingerprint: request_fingerprint.clone(),
                        contract_version,
                    }
                }
                (None, None) => CleanupOperationProvenanceV1::LegacyUnknown,
                _ => return Err(CleanupEnvelopeError::Invalid),
            };
            push_operation(&mut operations, &pending.operation_id, provenance);
            if let Some(cancel_operation_id) = &pending.cancel_operation_id {
                push_operation(
                    &mut operations,
                    cancel_operation_id,
                    CleanupOperationProvenanceV1::LegacyUnknown,
                );
            }
        }
        if let Some(pending) = &state.pending_stalled_stop {
            push_operation(
                &mut operations,
                &pending.operation_id,
                CleanupOperationProvenanceV1::Verified {
                    request_fingerprint: pending.request_fingerprint.clone(),
                    contract_version: pending.contract_version,
                },
            );
        }
        if let Some(pending) = &state.pending_compensation_stop {
            push_operation(
                &mut operations,
                &pending.operation_id,
                CleanupOperationProvenanceV1::LegacyUnknown,
            );
        }
        let envelope = Self {
            cleanup_contract_version: 1,
            lease_ids,
            redundant_session_ids: Vec::new(),
            operations,
            engine_role,
            background_reference,
        };
        if envelope.validate() {
            Ok(envelope)
        } else {
            Err(CleanupEnvelopeError::Invalid)
        }
    }

    pub(crate) fn validate(&self) -> bool {
        self.cleanup_contract_version == 1
            && valid_unique_ids(&self.lease_ids)
            && valid_unique_ids(&self.redundant_session_ids)
            && self.operations.len() <= 1024
            && self.operations.iter().all(|operation| {
                valid_id(&operation.operation_id)
                    && match &operation.provenance {
                        CleanupOperationProvenanceV1::Verified {
                            request_fingerprint,
                            contract_version,
                        } => {
                            valid_fingerprint(request_fingerprint)
                                && *contract_version > 0
                                && *contract_version <= i32::MAX as u32
                        }
                        CleanupOperationProvenanceV1::LegacyUnknown => true,
                    }
            })
            && self
                .operations
                .iter()
                .map(|operation| operation.operation_id.as_str())
                .collect::<HashSet<_>>()
                .len()
                == self.operations.len()
            && self.background_reference.as_deref().is_none_or(valid_id)
            && serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= MAX_CLEANUP_ENVELOPE_BYTES)
    }
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn push_operation(
    operations: &mut Vec<CleanupOperationV1>,
    operation_id: &str,
    provenance: CleanupOperationProvenanceV1,
) {
    if let Some(existing) = operations
        .iter_mut()
        .find(|existing| existing.operation_id == operation_id)
    {
        if matches!(
            existing.provenance,
            CleanupOperationProvenanceV1::LegacyUnknown
        ) && matches!(provenance, CleanupOperationProvenanceV1::Verified { .. })
        {
            existing.provenance = provenance;
        }
    } else {
        operations.push(CleanupOperationV1 {
            operation_id: operation_id.to_owned(),
            provenance,
        });
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
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
        && !contains_forbidden_content(value)
}

fn contains_forbidden_content(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "privatekey",
        "private_key",
        "access_token",
        "refresh_token",
        "install_secret",
        "authorization:",
        "bearer ",
        "[interface]",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

pub(crate) fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
