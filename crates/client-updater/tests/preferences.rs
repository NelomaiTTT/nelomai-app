use nelomai_client_updater::{FileUpdatePreferenceStore, UpdatePreferenceStore, UpdatePreferences};
use std::fs;
use tempfile::tempdir;

#[test]
fn missing_preferences_default_to_automatic_updates() {
    let directory = tempdir().unwrap();
    let store = FileUpdatePreferenceStore::new(directory.path().join("updates.json"));

    assert_eq!(store.load().unwrap(), UpdatePreferences::default());
    assert!(store.load().unwrap().automatic);
}

#[test]
fn preferences_are_replaced_atomically_with_private_permissions() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("updates.json");
    let store = FileUpdatePreferenceStore::new(&path);

    store.save(UpdatePreferences { automatic: false }).unwrap();
    assert_eq!(
        store.load().unwrap(),
        UpdatePreferences { automatic: false }
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
