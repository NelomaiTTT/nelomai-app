use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::Mutex,
};
use tempfile::NamedTempFile;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsProvider {
    #[default]
    Auto,
    Google,
    Yandex,
    Quad9,
}

impl DnsProvider {
    pub fn servers(self) -> Vec<IpAddr> {
        let servers = match self {
            Self::Auto => vec![
                Ipv4Addr::new(8, 8, 8, 8),
                Ipv4Addr::new(77, 88, 8, 8),
                Ipv4Addr::new(9, 9, 9, 9),
                Ipv4Addr::new(8, 8, 4, 4),
            ],
            Self::Google => vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
            Self::Yandex => vec![Ipv4Addr::new(77, 88, 8, 8), Ipv4Addr::new(77, 88, 8, 1)],
            Self::Quad9 => vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)],
        };
        servers.into_iter().map(IpAddr::V4).collect()
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default)]
pub struct AppPreferences {
    pub close_to_tray: bool,
    pub dns_provider: DnsProvider,
}

impl Default for AppPreferences {
    fn default() -> Self {
        Self {
            close_to_tray: true,
            dns_provider: DnsProvider::Auto,
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
        let mut current = self
            .current
            .lock()
            .map_err(|_| io::Error::other("preference lock poisoned"))?;
        let preferences = AppPreferences {
            close_to_tray: enabled,
            ..*current
        };
        save(&self.path, preferences)?;
        *current = preferences;
        Ok(preferences)
    }

    pub fn set_dns_provider(&self, provider: DnsProvider) -> io::Result<AppPreferences> {
        let mut current = self
            .current
            .lock()
            .map_err(|_| io::Error::other("preference lock poisoned"))?;
        let preferences = AppPreferences {
            dns_provider: provider,
            ..*current
        };
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
    fn preferences_default_and_persist_independently() {
        let directory = std::env::temp_dir().join(format!(
            "nelomai-preferences-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let path = directory.join("preferences.json");
        let store = AppPreferenceStore::new(&path);
        assert!(store.get().close_to_tray);
        assert_eq!(store.get().dns_provider, DnsProvider::Auto);

        store.set_close_to_tray(false).unwrap();
        store.set_dns_provider(DnsProvider::Quad9).unwrap();
        let restored = AppPreferenceStore::new(&path).get();
        assert!(!restored.close_to_tray);
        assert_eq!(restored.dns_provider, DnsProvider::Quad9);

        store.set_close_to_tray(true).unwrap();
        assert_eq!(store.get().dns_provider, DnsProvider::Quad9);

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn legacy_preferences_default_to_automatic_dns() {
        let directory = std::env::temp_dir().join(format!(
            "nelomai-legacy-preferences-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("preferences.json");
        fs::write(&path, br#"{"close_to_tray":false}"#).unwrap();

        let restored = AppPreferenceStore::new(&path).get();

        assert!(!restored.close_to_tray);
        assert_eq!(restored.dns_provider, DnsProvider::Auto);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn automatic_dns_covers_fallbacks_and_manual_modes_stay_with_one_provider() {
        assert_eq!(
            DnsProvider::Auto.servers(),
            ["8.8.8.8", "77.88.8.8", "9.9.9.9", "8.8.4.4"]
                .map(|value| value.parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            DnsProvider::Google.servers(),
            ["8.8.8.8", "8.8.4.4"].map(|value| value.parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            DnsProvider::Yandex.servers(),
            ["77.88.8.8", "77.88.8.1"].map(|value| value.parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            DnsProvider::Quad9.servers(),
            ["9.9.9.9", "149.112.112.112"].map(|value| value.parse::<IpAddr>().unwrap())
        );
    }
}
