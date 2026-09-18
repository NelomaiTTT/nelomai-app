//! One owner writes; runtimes read bounded tails without issuing auth commands.
use crate::RefreshDiagnosticV1;
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

const ROTATE_AT_BYTES: u64 = 64 * 1024;

pub(crate) fn append(directory: &Path, event: &RefreshDiagnosticV1) -> io::Result<()> {
    let mut encoded = serde_json::to_vec(event)?;
    encoded.push(b'\n');
    fs::create_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let current = directory.join("auth-refresh.jsonl");
    let previous = directory.join("auth-refresh.previous.jsonl");
    if current
        .metadata()
        .is_ok_and(|m| m.len().saturating_add(encoded.len() as u64) > ROTATE_AT_BYTES)
    {
        match fs::remove_file(&previous) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        fs::rename(&current, previous)?;
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(current)?.write_all(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_bounded_private_journal_and_keeps_original_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let event = RefreshDiagnosticV1 {
            timestamp_unix: 123,
            kind: "auth.refresh.complete".into(),
            operation_id: "11111111-1111-4111-8111-111111111111".into(),
            code: "saved".into(),
        };
        for _ in 0..2000 {
            append(dir.path(), &event).unwrap();
        }
        for name in ["auth-refresh.jsonl", "auth-refresh.previous.jsonl"] {
            let path = dir.path().join(name);
            assert!(path.metadata().unwrap().len() <= ROTATE_AT_BYTES);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            }
            for line in fs::read_to_string(path).unwrap().lines() {
                let saved: serde_json::Value = serde_json::from_str(line).unwrap();
                assert_eq!(saved["timestamp_unix"], 123);
                assert_eq!(saved["kind"], "auth.refresh.complete");
                assert_eq!(saved.as_object().unwrap().len(), 4);
            }
        }
    }
}
