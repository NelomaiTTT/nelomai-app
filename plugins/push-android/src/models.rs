use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushTokenResponse {
    pub token: String,
    pub permission_granted: bool,
}
