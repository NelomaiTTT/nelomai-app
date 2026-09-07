//! Bounded result contract returned by the common Kotlin native callback.
use nelomai_client_api::TokenResponse;
use nelomai_client_container::NativeAuthFailure;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum NativeBackgroundReplyV1 {
    Success {
        format: u8,
        value: Option<Box<TokenResponse>>,
    },
    Failure {
        format: u8,
        code: String,
    },
}

pub fn decode_background_reply(
    value: Result<Option<String>, ()>,
) -> Result<Option<TokenResponse>, NativeAuthFailure> {
    let value = value
        .map_err(|_| NativeAuthFailure::OutcomeUnknown)?
        .ok_or(NativeAuthFailure::OutcomeUnknown)?;
    if value.len() > 65536 {
        return Err(NativeAuthFailure::OutcomeUnknown);
    }
    match serde_json::from_str(&value).map_err(|_| NativeAuthFailure::OutcomeUnknown)? {
        NativeBackgroundReplyV1::Success { format: 1, value } => Ok(value.map(|value| *value)),
        NativeBackgroundReplyV1::Failure { format: 1, code } => Err(match code.as_str() {
            "invalid_background_token"
            | "invalid_background_recovery"
            | "activation_not_applied"
            | "background_recovery_unsupported"
            | "background_owner_scope_mismatch"
            | "background_credential_unavailable" => NativeAuthFailure::NotIssued,
            "app_access_unavailable" => NativeAuthFailure::AccessUnavailable,
            _ => NativeAuthFailure::OutcomeUnknown,
        }),
        _ => Err(NativeAuthFailure::OutcomeUnknown),
    }
}
