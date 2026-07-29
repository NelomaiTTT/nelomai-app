use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallApkRequest {
    pub path: String,
    pub expected_version: String,
    pub expected_signer_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallApkResponse {
    pub installer_opened: bool,
}
