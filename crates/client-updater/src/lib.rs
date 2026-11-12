use async_trait::async_trait;
mod android;
mod prepared;
pub use android::{AndroidApkInstaller, AndroidUpdateBackend};
use nelomai_client_api::AccessSnapshot;
use nelomai_contracts::UpdateState;
pub use prepared::{
    DownloadValidator, PartialDownload, PreparedCache, PreparedUpdate, ResolvedUpdate,
    ResumedDownload, StagedFile,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use url::Url;

const UPDATE_API_PATH: &str = "/api/client/v1/updates/";
const UPDATE_ARTIFACT_PATH: &str = "/api/client/v1/updates/artifacts/";
const MAX_ANDROID_APK_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct UpdateEndpointPolicy {
    panel_origin: Url,
}

#[derive(Debug, Error)]
pub enum UpdateEndpointError {
    #[error("panel update URL is invalid")]
    InvalidPanelUrl,
    #[error("update endpoint value is invalid")]
    InvalidEndpointValue,
}

impl UpdateEndpointPolicy {
    pub fn new(panel_base: &str) -> Result<Self, UpdateEndpointError> {
        let panel_origin =
            Url::parse(panel_base).map_err(|_| UpdateEndpointError::InvalidPanelUrl)?;
        if panel_origin.scheme() != "https"
            || panel_origin.host_str().is_none()
            || !panel_origin.username().is_empty()
            || panel_origin.password().is_some()
            || panel_origin.query().is_some()
            || panel_origin.fragment().is_some()
            || panel_origin.path() != "/"
        {
            return Err(UpdateEndpointError::InvalidPanelUrl);
        }
        Ok(Self { panel_origin })
    }

    pub fn manifest_url(
        &self,
        target: &str,
        current_version: &str,
    ) -> Result<Url, UpdateEndpointError> {
        if !valid_endpoint_value(target) || !valid_endpoint_value(current_version) {
            return Err(UpdateEndpointError::InvalidEndpointValue);
        }
        let mut endpoint = self.panel_origin.clone();
        endpoint.set_path(UPDATE_API_PATH);
        endpoint
            .path_segments_mut()
            .map_err(|_| UpdateEndpointError::InvalidPanelUrl)?
            .pop_if_empty()
            .extend(["manifest", target, current_version]);
        Ok(endpoint)
    }

    pub fn is_trusted_artifact(&self, artifact: &Url) -> bool {
        let approved_backup = nelomai_client_api::panel_backup_url(&self.panel_origin);
        artifact.scheme() == self.panel_origin.scheme()
            && (artifact.host_str() == self.panel_origin.host_str()
                || approved_backup
                    .as_ref()
                    .is_some_and(|backup| artifact.host_str() == backup.host_str()))
            && artifact.port_or_known_default() == self.panel_origin.port_or_known_default()
            && artifact.username().is_empty()
            && artifact.password().is_none()
            && artifact.query().is_none()
            && artifact.fragment().is_none()
            && artifact
                .path()
                .strip_prefix(UPDATE_ARTIFACT_PATH)
                .is_some_and(|name| !name.is_empty() && !name.contains('/'))
    }
}

fn valid_endpoint_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

#[derive(Debug, Clone, Deserialize)]
pub struct AndroidUpdateManifest {
    pub version: String,
    pub url: String,
    pub signature: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAndroidUpdate {
    pub version: String,
    pub artifact_url: Url,
    pub signer_sha256: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AndroidManifestError {
    #[error("Android update version is invalid")]
    InvalidVersion,
    #[error("Android update version changed")]
    VersionChanged,
    #[error("Android update artifact URL is invalid")]
    InvalidArtifactUrl,
    #[error("Android update artifact is not trusted")]
    UntrustedArtifact,
    #[error("Android update hash is invalid")]
    InvalidHash,
    #[error("Android update signer is invalid")]
    InvalidSigner,
    #[error("Android update size is invalid")]
    InvalidSize,
}

impl AndroidUpdateManifest {
    pub fn validate(
        self,
        expected_version: &str,
        endpoint_policy: &UpdateEndpointPolicy,
    ) -> Result<ValidatedAndroidUpdate, AndroidManifestError> {
        Version::parse(&self.version).map_err(|_| AndroidManifestError::InvalidVersion)?;
        if self.version != expected_version {
            return Err(AndroidManifestError::VersionChanged);
        }
        let artifact_url =
            Url::parse(&self.url).map_err(|_| AndroidManifestError::InvalidArtifactUrl)?;
        if !endpoint_policy.is_trusted_artifact(&artifact_url) {
            return Err(AndroidManifestError::UntrustedArtifact);
        }
        let sha256 = self.sha256.trim().to_ascii_lowercase();
        if !valid_sha256(&sha256) {
            return Err(AndroidManifestError::InvalidHash);
        }
        let signer_sha256 = self.signature.trim().to_ascii_lowercase();
        if !valid_sha256(&signer_sha256) {
            return Err(AndroidManifestError::InvalidSigner);
        }
        if self.size_bytes == 0 || self.size_bytes > MAX_ANDROID_APK_BYTES {
            return Err(AndroidManifestError::InvalidSize);
        }
        Ok(ValidatedAndroidUpdate {
            version: self.version,
            artifact_url,
            signer_sha256,
            sha256,
            size_bytes: self.size_bytes,
        })
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateOffer {
    pub version: String,
    pub notes: Option<String>,
    pub required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UpdateOfferError {
    #[error("available update is missing its version")]
    MissingVersion,
    #[error("available update version is invalid")]
    InvalidVersion,
}

impl UpdateOffer {
    pub fn from_state(state: &UpdateState) -> Result<Option<Self>, UpdateOfferError> {
        if !state.update_available {
            return Ok(None);
        }
        let version = state
            .current_version
            .as_ref()
            .ok_or(UpdateOfferError::MissingVersion)?;
        Version::parse(version).map_err(|_| UpdateOfferError::InvalidVersion)?;
        Ok(Some(Self {
            version: version.clone(),
            notes: state.release_notes.clone(),
            required: state.required,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdatePhase {
    Idle,
    Available(UpdateOffer),
    Downloading {
        version: String,
        downloaded: u64,
        total: Option<u64>,
    },
    ReadyToInstall {
        version: String,
    },
    Installing {
        version: String,
    },
    ReadyToRestart {
        version: String,
    },
    AwaitingInstallation {
        version: String,
    },
    Failed {
        version: String,
        code: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadProgress {
    pub downloaded: u64,
    pub total: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledUpdate {
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallResult {
    NoUpdate,
    Installed(InstalledUpdate),
    InstallerOpened(InstalledUpdate),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("update backend failed: {code}")]
pub struct UpdateBackendError {
    code: String,
    stage: Option<&'static str>,
    progress: Option<DownloadProgress>,
}

impl UpdateBackendError {
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            stage: None,
            progress: None,
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn manifest_temporarily_unavailable() -> Self {
        Self::new("update_manifest_temporarily_unavailable")
    }

    pub fn is_manifest_temporarily_unavailable(&self) -> bool {
        self.code == "update_manifest_temporarily_unavailable"
    }

    pub fn at_stage(mut self, stage: &'static str) -> Self {
        if self.stage.is_none() {
            self.stage = Some(stage);
        }
        self
    }

    pub fn stage(&self) -> Option<&'static str> {
        self.stage
    }

    pub fn with_progress(mut self, progress: DownloadProgress) -> Self {
        self.progress = Some(progress);
        self
    }

    pub fn progress(&self) -> Option<DownloadProgress> {
        self.progress
    }
}

#[async_trait]
pub trait UpdateBackend: Send + Sync {
    async fn resolve(
        &self,
        _access: &AccessSnapshot,
        _expected_version: &str,
    ) -> Result<Option<ResolvedUpdate>, UpdateBackendError> {
        Err(UpdateBackendError::new("update_protocol_unsupported"))
    }
    async fn prepare(
        &self,
        _access: &AccessSnapshot,
        _resolved: &ResolvedUpdate,
        _progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<PreparedUpdate, UpdateBackendError> {
        Err(UpdateBackendError::new("update_protocol_unsupported"))
    }
    async fn install_prepared(
        &self,
        _prepared: &PreparedUpdate,
        _barrier: UpdateBarrierPhase,
    ) -> Result<InstallResult, UpdateBackendError> {
        Err(UpdateBackendError::new("update_protocol_unsupported"))
    }
    // Source compatibility while Android's adapter is ported. The consent
    // coordinator never calls this combined download/install operation.

    async fn install(
        &self,
        _access_token: &AccessSnapshot,
        _expected_version: &str,
        _barrier: UpdateBarrierPhase,
        _progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        Err(UpdateBackendError::new("update_consent_required"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateBarrierPhase {
    LocalStopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("update barrier failed: {code}")]
pub struct UpdateBarrierError {
    code: String,
}

impl UpdateBarrierError {
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

#[async_trait]
pub trait UpdateInstallBarrier: Send + Sync {
    /// Owner validates the current authenticated scope after each external await.
    /// Default is fail-closed for an adapter that has not adopted consent yet.
    async fn validate_authority(&self, _access: &AccessSnapshot) -> Result<(), UpdateBarrierError> {
        Err(UpdateBarrierError::new("update_authority_unavailable"))
    }

    async fn prepare(&self, target_version: &str)
        -> Result<UpdateBarrierPhase, UpdateBarrierError>;
    async fn installer_opened(&self) -> Result<(), UpdateBarrierError>;
    async fn installer_failed(&self) -> Result<(), UpdateBarrierError>;
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error(transparent)]
    Backend(#[from] UpdateBackendError),
    #[error(transparent)]
    Barrier(#[from] UpdateBarrierError),
}

/// Fixed error codes that may be recorded and attached to support reports.
pub fn is_diagnostic_error_code(code: &str) -> bool {
    matches!(
        code,
        "common_installer_untrusted"
            | "helper_owner_is_root"
            | "installed_update_version_mismatch"
            | "invalid_update_endpoint"
            | "untrusted_update_artifact"
            | "unsupported_update_package"
            | "unsupported_update_target"
            | "update_auth_changed"
            | "update_authority_unavailable"
            | "update_cache_invalid"
            | "update_cache_unavailable"
            | "update_check_failed"
            | "update_consent_required"
            | "update_download_encoding_invalid"
            | "update_download_failed"
            | "update_download_http_rejected"
            | "update_download_http_server_error"
            | "update_download_http_unauthorized"
            | "update_download_http_unavailable"
            | "update_download_incomplete"
            | "update_download_interrupted"
            | "update_download_length_invalid"
            | "update_download_range_invalid"
            | "update_download_request_failed"
            | "update_download_timeout"
            | "update_hash_mismatch"
            | "update_identity_invalid"
            | "update_install_failed"
            | "update_install_in_progress"
            | "update_install_outcome_unknown"
            | "update_journal_failed"
            | "update_manifest_temporarily_unavailable"
            | "update_offer_changed"
            | "update_operation_failed"
            | "update_package_in_use"
            | "update_package_too_large"
            | "update_protocol_unsupported"
            | "update_recovery_failed"
            | "update_shutdown_failed"
            | "update_signature_invalid"
            | "update_staging_failed"
            | "update_stop_proof_changed"
            | "update_stop_proof_unavailable"
            | "update_transport_unavailable"
            | "update_ui_background"
            | "update_verification_failed"
            | "update_version_changed"
            | "updater_authorization_failed"
            | "updater_configuration_failed"
            | "updater_public_key_missing"
    )
}

mod coordinator;
pub use coordinator::UpdateCoordinator;

fn automatic_by_default() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePreferences {
    #[serde(default = "automatic_by_default")]
    pub automatic: bool,
}

impl Default for UpdatePreferences {
    fn default() -> Self {
        Self { automatic: true }
    }
}

#[derive(Debug, Error)]
pub enum UpdatePreferenceError {
    #[error("update preference I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("stored update preferences are invalid: {0}")]
    InvalidData(#[from] serde_json::Error),
}

pub trait UpdatePreferenceStore {
    fn load(&self) -> Result<UpdatePreferences, UpdatePreferenceError>;
    fn save(&self, preferences: UpdatePreferences) -> Result<(), UpdatePreferenceError>;
}

pub struct FileUpdatePreferenceStore {
    path: PathBuf,
}

impl FileUpdatePreferenceStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl UpdatePreferenceStore for FileUpdatePreferenceStore {
    fn load(&self) -> Result<UpdatePreferences, UpdatePreferenceError> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Ok(UpdatePreferences::default())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn save(&self, preferences: UpdatePreferences) -> Result<(), UpdatePreferenceError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent path"))?;
        create_private_directory(parent)?;
        let mut temporary = NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        serde_json::to_writer(temporary.as_file_mut(), &preferences)?;
        temporary.as_file_mut().flush()?;
        temporary.as_file().sync_all()?;
        temporary.persist(&self.path).map_err(|error| error.error)?;
        Ok(())
    }
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
