use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tempfile::NamedTempFile;

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default)]
pub struct AppPreferences {
    pub close_to_tray: bool,
}

impl Default for AppPreferences {
    fn default() -> Self {
        Self {
            close_to_tray: true,
        }
    }
}

pub struct AppPreferenceStore {
    path: PathBuf,
    current: Mutex<AppPreferences>,
}

impl AppPreferenceStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let current = load(&path).unwrap_or_default();
        Self {
            path,
            current: Mutex::new(current),
        }
    }

    pub fn get(&self) -> AppPreferences {
        self.current
            .lock()
            .map(|preferences| *preferences)
            .unwrap_or_default()
    }

    pub fn set_close_to_tray(&self, enabled: bool) -> io::Result<AppPreferences> {
        let preferences = AppPreferences {
            close_to_tray: enabled,
        };
        let mut current = self
            .current
            .lock()
            .map_err(|_| io::Error::other("preference lock poisoned"))?;
        save(&self.path, preferences)?;
        *current = preferences;
        Ok(preferences)
    }
}

fn load(path: &Path) -> io::Result<AppPreferences> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(AppPreferences::default()),
        Err(error) => Err(error),
    }
}

fn save(path: &Path, preferences: AppPreferences) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent path"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    serde_json::to_writer(temporary.as_file_mut(), &preferences).map_err(io::Error::other)?;
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_to_tray_defaults_to_enabled_and_persists() {
        let directory = std::env::temp_dir().join(format!(
            "nelomai-preferences-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let path = directory.join("preferences.json");
        let store = AppPreferenceStore::new(&path);
        assert!(store.get().close_to_tray);

        store.set_close_to_tray(false).unwrap();
        assert!(!AppPreferenceStore::new(&path).get().close_to_tray);

        let _ = fs::remove_dir_all(directory);
    }
}
