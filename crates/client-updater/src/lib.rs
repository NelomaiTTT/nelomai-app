use async_trait::async_trait;
use nelomai_contracts::UpdateState;
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
        artifact.scheme() == self.panel_origin.scheme()
            && artifact.host_str() == self.panel_origin.host_str()
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
    ReadyToRestart {
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
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("update backend failed: {code}")]
pub struct UpdateBackendError {
    code: String,
}

impl UpdateBackendError {
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }

    pub fn code(&self) -> &str {
        &self.code
    }
}

#[async_trait]
pub trait UpdateBackend: Send + Sync {
    async fn install(
        &self,
        access_token: &str,
        expected_version: &str,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError>;
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error(transparent)]
    Backend(#[from] UpdateBackendError),
}

pub struct UpdateCoordinator<B> {
    backend: Arc<B>,
    phase: Arc<Mutex<UpdatePhase>>,
    offer: Mutex<Option<UpdateOffer>>,
    install_gate: AsyncMutex<()>,
}

impl<B: UpdateBackend> UpdateCoordinator<B> {
    pub fn new(backend: Arc<B>) -> Self {
        Self {
            backend,
            phase: Arc::new(Mutex::new(UpdatePhase::Idle)),
            offer: Mutex::new(None),
            install_gate: AsyncMutex::new(()),
        }
    }

    pub fn observe(&self, offer: Option<UpdateOffer>) {
        let mut current_offer = self.offer.lock().expect("update offer lock poisoned");
        let mut phase = self.phase.lock().expect("update phase lock poisoned");
        *current_offer = offer.clone();
        match (&*phase, offer) {
            (UpdatePhase::ReadyToRestart { version }, Some(offer)) if version == &offer.version => {
            }
            (UpdatePhase::Downloading { .. }, _) => {}
            (_, Some(offer)) => *phase = UpdatePhase::Available(offer),
            (_, None) => *phase = UpdatePhase::Idle,
        }
    }

    pub fn phase(&self) -> UpdatePhase {
        self.phase
            .lock()
            .expect("update phase lock poisoned")
            .clone()
    }

    pub async fn install_automatically(
        &self,
        access_token: &str,
        preferences: UpdatePreferences,
    ) -> Result<UpdatePhase, UpdateError> {
        if !preferences.automatic {
            return Ok(self.phase());
        }
        self.install_now(access_token).await
    }

    pub async fn install_now(&self, access_token: &str) -> Result<UpdatePhase, UpdateError> {
        let _guard = self.install_gate.lock().await;
        if matches!(self.phase(), UpdatePhase::ReadyToRestart { .. }) {
            return Ok(self.phase());
        }
        let Some(offer) = self
            .offer
            .lock()
            .expect("update offer lock poisoned")
            .clone()
        else {
            return Ok(UpdatePhase::Idle);
        };

        *self.phase.lock().expect("update phase lock poisoned") = UpdatePhase::Downloading {
            version: offer.version.clone(),
            downloaded: 0,
            total: None,
        };
        let phase = self.phase.clone();
        let progress_version = offer.version.clone();
        let progress = Arc::new(move |progress: DownloadProgress| {
            *phase.lock().expect("update phase lock poisoned") = UpdatePhase::Downloading {
                version: progress_version.clone(),
                downloaded: progress.downloaded,
                total: progress.total,
            };
        });

        match self
            .backend
            .install(access_token, &offer.version, progress)
            .await
        {
            Ok(InstallResult::NoUpdate) => {
                *self.offer.lock().expect("update offer lock poisoned") = None;
                *self.phase.lock().expect("update phase lock poisoned") = UpdatePhase::Idle;
                Ok(UpdatePhase::Idle)
            }
            Ok(InstallResult::Installed(installed)) => {
                if installed.version != offer.version {
                    let error = UpdateBackendError::new("installed_update_version_mismatch");
                    *self.phase.lock().expect("update phase lock poisoned") = UpdatePhase::Failed {
                        version: offer.version,
                        code: error.code().to_string(),
                    };
                    return Err(error.into());
                }
                let phase = UpdatePhase::ReadyToRestart {
                    version: installed.version,
                };
                *self.phase.lock().expect("update phase lock poisoned") = phase.clone();
                Ok(phase)
            }
            Err(error) => {
                let phase = UpdatePhase::Failed {
                    version: offer.version,
                    code: error.code().to_string(),
                };
                *self.phase.lock().expect("update phase lock poisoned") = phase;
                Err(error.into())
            }
        }
    }
}

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
