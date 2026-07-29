use crate::platform;
use nelomai_client_updater::{
    FileUpdatePreferenceStore, UpdateCoordinator, UpdateOffer, UpdatePhase, UpdatePreferenceStore,
    UpdatePreferences,
};
use nelomai_contracts::UpdateState;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, Wry};

pub struct NativeUpdater {
    preferences: FileUpdatePreferenceStore,
    current_preferences: Mutex<UpdatePreferences>,
    observed_offer: Mutex<Option<UpdateOffer>>,
    #[cfg(desktop)]
    coordinator: Option<UpdateCoordinator<platform::updater::DesktopUpdateBackend<Wry>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatusResponse {
    pub supported: bool,
    pub automatic: bool,
    pub phase: &'static str,
    pub version: Option<String>,
    pub notes: Option<String>,
    pub required: bool,
    pub downloaded: u64,
    pub total: Option<u64>,
    pub error_code: Option<String>,
}

impl NativeUpdater {
    pub fn from_build(app: &AppHandle<Wry>) -> Result<Self, tauri::Error> {
        let preferences = FileUpdatePreferenceStore::new(
            app.path()
                .app_data_dir()?
                .join("updates")
                .join("preferences.json"),
        );
        let current_preferences = preferences.load().unwrap_or_default();
        #[cfg(desktop)]
        let coordinator = platform::updater::DesktopUpdateBackend::from_build(app.clone())
            .ok()
            .map(|backend| UpdateCoordinator::new(Arc::new(backend)));

        Ok(Self {
            preferences,
            current_preferences: Mutex::new(current_preferences),
            observed_offer: Mutex::new(None),
            #[cfg(desktop)]
            coordinator,
        })
    }

    pub fn observe(&self, state: &UpdateState) -> Result<(), String> {
        let offer = UpdateOffer::from_state(state).map_err(|error| error.to_string())?;
        *self
            .observed_offer
            .lock()
            .map_err(|_| "update offer lock poisoned".to_string())? = offer.clone();
        #[cfg(desktop)]
        if let Some(coordinator) = &self.coordinator {
            coordinator.observe(offer);
        }
        Ok(())
    }

    pub fn status(&self) -> Result<UpdateStatusResponse, String> {
        let preferences = *self
            .current_preferences
            .lock()
            .map_err(|_| "update preference lock poisoned".to_string())?;
        let observed_offer = self
            .observed_offer
            .lock()
            .map_err(|_| "update offer lock poisoned".to_string())?
            .clone();

        #[cfg(desktop)]
        if let Some(coordinator) = &self.coordinator {
            return Ok(status_from_phase(
                true,
                preferences,
                coordinator.phase(),
                observed_offer,
            ));
        }

        Ok(status_from_phase(
            false,
            preferences,
            observed_offer
                .clone()
                .map(UpdatePhase::Available)
                .unwrap_or(UpdatePhase::Idle),
            observed_offer,
        ))
    }

    pub fn set_automatic(&self, automatic: bool) -> Result<UpdateStatusResponse, String> {
        let preferences = UpdatePreferences { automatic };
        self.preferences
            .save(preferences)
            .map_err(|error| error.to_string())?;
        *self
            .current_preferences
            .lock()
            .map_err(|_| "update preference lock poisoned".to_string())? = preferences;
        self.status()
    }

    pub async fn install_automatically(
        &self,
        access_token: &str,
    ) -> Result<UpdateStatusResponse, String> {
        let preferences = *self
            .current_preferences
            .lock()
            .map_err(|_| "update preference lock poisoned".to_string())?;
        #[cfg(desktop)]
        if let Some(coordinator) = &self.coordinator {
            coordinator
                .install_automatically(access_token, preferences)
                .await
                .map_err(|error| error.to_string())?;
        }
        self.status()
    }

    pub async fn install_now(&self, access_token: &str) -> Result<UpdateStatusResponse, String> {
        #[cfg(desktop)]
        if let Some(coordinator) = &self.coordinator {
            coordinator
                .install_now(access_token)
                .await
                .map_err(|error| error.to_string())?;
            return self.status();
        }

        let _ = access_token;
        Err("update backend is unavailable on this platform".to_string())
    }

    pub fn ready_to_restart(&self) -> bool {
        #[cfg(desktop)]
        if let Some(coordinator) = &self.coordinator {
            return matches!(coordinator.phase(), UpdatePhase::ReadyToRestart { .. });
        }
        false
    }
}

fn status_from_phase(
    supported: bool,
    preferences: UpdatePreferences,
    phase: UpdatePhase,
    observed_offer: Option<UpdateOffer>,
) -> UpdateStatusResponse {
    let (phase_name, version, downloaded, total, error_code) = match phase {
        UpdatePhase::Idle => ("idle", None, 0, None, None),
        UpdatePhase::Available(offer) => ("available", Some(offer.version), 0, None, None),
        UpdatePhase::Downloading {
            version,
            downloaded,
            total,
        } => ("downloading", Some(version), downloaded, total, None),
        UpdatePhase::ReadyToRestart { version } => {
            ("ready_to_restart", Some(version), 0, None, None)
        }
        UpdatePhase::Failed { version, code } => ("failed", Some(version), 0, None, Some(code)),
    };
    UpdateStatusResponse {
        supported,
        automatic: preferences.automatic,
        phase: phase_name,
        version,
        notes: observed_offer
            .as_ref()
            .and_then(|offer| offer.notes.clone()),
        required: observed_offer.as_ref().is_some_and(|offer| offer.required),
        downloaded,
        total,
        error_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> UpdateOffer {
        UpdateOffer {
            version: "0.2.0".to_string(),
            notes: Some("Исправлена работа подключения.".to_string()),
            required: true,
        }
    }

    #[test]
    fn downloading_status_keeps_offer_metadata() {
        let response = status_from_phase(
            true,
            UpdatePreferences { automatic: false },
            UpdatePhase::Downloading {
                version: "0.2.0".to_string(),
                downloaded: 40,
                total: Some(100),
            },
            Some(offer()),
        );

        assert!(response.supported);
        assert!(!response.automatic);
        assert_eq!(response.phase, "downloading");
        assert_eq!(response.version.as_deref(), Some("0.2.0"));
        assert_eq!(response.downloaded, 40);
        assert_eq!(response.total, Some(100));
        assert!(response.required);
        assert_eq!(
            response.notes.as_deref(),
            Some("Исправлена работа подключения.")
        );
    }

    #[test]
    fn unsupported_platform_still_reports_the_available_version() {
        let response = status_from_phase(
            false,
            UpdatePreferences::default(),
            UpdatePhase::Available(offer()),
            Some(offer()),
        );

        assert!(!response.supported);
        assert_eq!(response.phase, "available");
        assert_eq!(response.version.as_deref(), Some("0.2.0"));
    }
}
