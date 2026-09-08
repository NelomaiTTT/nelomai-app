//! Large records over bounded Windows Credential Manager entries.
use crate::StorageError;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"NLMCRD1\0";
const CHUNK: usize = 2400;
const MAX: usize = 8 * 1024 * 1024;
#[derive(PartialEq, Eq)]
struct Index {
    generation: [u8; 16],
    len: usize,
    digest: [u8; 32],
}
fn invalid() -> StorageError {
    StorageError::RecoveryRequired("Windows protected record is incomplete or corrupt")
}
impl Index {
    fn parse(bytes: &[u8]) -> Result<Option<Self>, StorageError> {
        if !bytes.starts_with(MAGIC) {
            return Ok(None);
        }
        if bytes.len() != 60 {
            return Err(invalid());
        }
        let len = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
        if len == 0 || len > MAX {
            return Err(invalid());
        }
        Ok(Some(Self {
            generation: bytes[8..24].try_into().unwrap(),
            len,
            digest: bytes[28..60].try_into().unwrap(),
        }))
    }
    fn encode(&self) -> Vec<u8> {
        [
            MAGIC.as_slice(),
            &self.generation,
            &(self.len as u32).to_le_bytes(),
            &self.digest,
        ]
        .concat()
    }
    fn count(&self) -> usize {
        self.len.div_ceil(CHUNK)
    }
    fn key(&self, account: &str, n: usize) -> String {
        let generation: String = self.generation.iter().map(|v| format!("{v:02x}")).collect();
        format!("{account}:chunk-v1:{generation}:{n}")
    }
    fn cleanup(&self, store: &impl Entries, account: &str) -> Result<(), StorageError> {
        for n in 0..self.count() {
            store.remove(&self.key(account, n))?;
        }
        Ok(())
    }
    fn read(&self, store: &impl Entries, account: &str) -> Result<Vec<u8>, StorageError> {
        let mut bytes = Vec::with_capacity(self.len);
        for n in 0..self.count() {
            let chunk = store.read(&self.key(account, n))?.ok_or_else(invalid)?;
            if chunk.len() != (self.len - n * CHUNK).min(CHUNK) {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk);
        }
        if Sha256::digest(&bytes).as_slice() != self.digest {
            return Err(invalid());
        }
        Ok(bytes)
    }
}

pub(super) trait Entries {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StorageError>;
    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), StorageError>;
    fn remove(&self, name: &str) -> Result<(), StorageError>;
}
fn pending_key(account: &str) -> String {
    format!("{account}:chunk-transaction-v1")
}
// Two bounded indexes, never plaintext secrets. Persist before writing parts so
// a crash cannot orphan credentials, including when the next operation is logout.
fn begin(
    store: &impl Entries,
    account: &str,
    previous: Option<&Index>,
    next: Option<&Index>,
) -> Result<(), StorageError> {
    if previous.is_none() && next.is_none() {
        return Ok(());
    }
    let bytes: Vec<u8> = [previous, next]
        .into_iter()
        .flat_map(|index| index.map(Index::encode).unwrap_or_else(|| vec![0; 60]))
        .collect();
    store.write(&pending_key(account), &bytes)
}
// Mutations use the existing auth/runtime owner's single-writer gate. Readers
// must not run this recovery: they may overlap an in-progress publication.
fn finish(store: &impl Entries, account: &str) -> Result<(), StorageError> {
    let Some(pending) = store.read(&pending_key(account))? else {
        return Ok(());
    };
    if pending.len() != 120 {
        return Err(invalid());
    }
    let indexes = pending
        .chunks_exact(60)
        .map(|bytes| {
            if bytes == [0; 60] {
                Ok(None)
            } else {
                Ok(Some(Index::parse(bytes)?.ok_or_else(invalid)?))
            }
        })
        .collect::<Result<Vec<_>, StorageError>>()?;
    let current = store
        .read(account)?
        .as_deref()
        .map(Index::parse)
        .transpose()?
        .flatten();
    for index in indexes.into_iter().flatten() {
        if current.as_ref() != Some(&index) {
            index.cleanup(store, account)?;
        }
    }
    store.remove(&pending_key(account))
}
pub(super) fn load(store: &impl Entries, account: &str) -> Result<Option<Vec<u8>>, StorageError> {
    // A concurrent reader may have seen the old index just before publication
    // and cleanup. Retry only when that authoritative index actually changed.
    for _ in 0..3 {
        let Some(root) = store.read(account)? else {
            return Ok(None);
        };
        let Some(index) = Index::parse(&root)? else {
            return Ok(Some(root));
        };
        let result = index.read(store, account);
        if result.is_ok() || store.read(account)?.as_deref() == Some(root.as_slice()) {
            return result.map(Some);
        }
    }
    Err(invalid())
}
pub(super) fn save(store: &impl Entries, account: &str, bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.len() > MAX {
        return Err(invalid());
    }
    finish(store, account)?;
    let previous = store
        .read(account)?
        .as_deref()
        .map(Index::parse)
        .transpose()?
        .flatten();
    let next = if bytes.len() > 2560 || bytes.starts_with(MAGIC) {
        Some(Index {
            generation: rand::random(),
            len: bytes.len(),
            digest: Sha256::digest(bytes).into(),
        })
    } else {
        None
    };
    begin(store, account, previous.as_ref(), next.as_ref())?;
    if let Some(index) = &next {
        for (n, chunk) in bytes.chunks(CHUNK).enumerate() {
            if let Err(error) = store.write(&index.key(account, n), chunk) {
                let _ = finish(store, account);
                return Err(error);
            }
        }
    }
    let root = next.as_ref().map(Index::encode);
    if let Err(error) = store.write(account, root.as_deref().unwrap_or(bytes)) {
        let _ = finish(store, account);
        return Err(error);
    }
    // CredWrite publishes one root atomically. Cleanup cannot turn a committed
    // save into a reported failure. The pending record retains cleanup work.
    let _ = finish(store, account);
    Ok(())
}
pub(super) fn delete(store: &impl Entries, account: &str) -> Result<(), StorageError> {
    finish(store, account)?;
    let previous = store
        .read(account)?
        .as_deref()
        .map(Index::parse)
        .transpose()?
        .flatten();
    begin(store, account, previous.as_ref(), None)?;
    store.remove(account)?;
    finish(store, account)
}

#[cfg(windows)]
pub(super) struct WindowsEntries;
#[cfg(windows)]
impl Entries for WindowsEntries {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let entry = keyring::Entry::new(crate::SERVICE_NAME, name)
            .map_err(|e| StorageError::Keyring(e.to_string()))?;
        match entry.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(StorageError::Keyring(error.to_string())),
        }
    }
    fn write(&self, name: &str, bytes: &[u8]) -> Result<(), StorageError> {
        keyring::Entry::new(crate::SERVICE_NAME, name)
            .and_then(|e| e.set_secret(bytes))
            .map_err(|e| StorageError::Keyring(e.to_string()))
    }
    fn remove(&self, name: &str) -> Result<(), StorageError> {
        match keyring::Entry::new(crate::SERVICE_NAME, name).and_then(|e| e.delete_credential()) {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(StorageError::Keyring(error.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    #[derive(Default)]
    struct Memory {
        values: RefCell<BTreeMap<String, Vec<u8>>>,
        fail_write: Cell<Option<usize>>,
        crash_write: Cell<Option<usize>>,
        fail_remove: Cell<bool>,
        writes: Cell<usize>,
    }
    impl Entries for Memory {
        fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.values.borrow().get(name).cloned())
        }
        fn write(&self, name: &str, bytes: &[u8]) -> Result<(), StorageError> {
            let n = self.writes.get() + 1;
            self.writes.set(n);
            assert_ne!(
                self.crash_write.get(),
                Some(n),
                "simulated process termination"
            );
            if bytes.len() > 2560 || self.fail_write.get() == Some(n) {
                return Err(StorageError::Keyring("bounded write refused".into()));
            }
            self.values.borrow_mut().insert(name.into(), bytes.into());
            Ok(())
        }
        fn remove(&self, name: &str) -> Result<(), StorageError> {
            if self.fail_remove.get() {
                return Err(StorageError::Keyring("remove refused".into()));
            }
            self.values.borrow_mut().remove(name);
            Ok(())
        }
    }
    #[test]
    fn large_records_roundtrip_without_exceeding_windows_entry_limit() {
        let store = Memory::default();
        for size in [0, 2560, 2561, 7500, 20000, 16] {
            let data: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
            save(&store, "primary:auth-v1", &data).unwrap();
            assert_eq!(load(&store, "primary:auth-v1").unwrap(), Some(data));
        }
        delete(&store, "primary:auth-v1").unwrap();
        assert!(load(&store, "primary:auth-v1").unwrap().is_none());
        assert!(store.values.borrow().is_empty());
    }
    #[test]
    fn interrupted_replacement_keeps_previous_record() {
        for failure in 1..=6 {
            let store = Memory::default();
            save(&store, "record", b"legacy-json").unwrap();
            store.fail_write.set(Some(store.writes.get() + failure));
            let result = save(&store, "record", &vec![7; 7500]);
            assert!(result.is_err());
            assert_eq!(
                load(&store, "record").unwrap(),
                Some(b"legacy-json".to_vec())
            );
            assert_eq!(store.values.borrow().len(), 1);
        }
    }
    #[test]
    fn deletion_cleans_parts_after_process_termination() {
        for crash in 1..=7 {
            let store = Memory::default();
            save(&store, "record", &vec![1; 7500]).unwrap();
            store.crash_write.set(Some(store.writes.get() + crash));
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                save(&store, "record", &vec![2; 10000]).unwrap();
            }));
            store.crash_write.set(None);
            delete(&store, "record").unwrap();
            assert!(
                store.values.borrow().is_empty(),
                "orphan secrets at crash {crash}"
            );
        }
    }
    #[test]
    fn committed_save_survives_cleanup_failure_and_logout_retries_cleanup() {
        let store = Memory::default();
        save(&store, "record", &vec![1; 7500]).unwrap();
        store.fail_remove.set(true);
        save(&store, "record", &vec![2; 10000]).unwrap();
        assert_eq!(load(&store, "record").unwrap(), Some(vec![2; 10000]));
        assert!(delete(&store, "record").is_err());
        store.fail_remove.set(false);
        delete(&store, "record").unwrap();
        assert!(store.values.borrow().is_empty());
    }
    #[test]
    fn reserved_prefix_roundtrips_and_oversized_write_keeps_old_record() {
        let store = Memory::default();
        save(&store, "record", MAGIC).unwrap();
        assert_eq!(load(&store, "record").unwrap(), Some(MAGIC.to_vec()));
        assert!(save(&store, "record", &vec![0; MAX + 1]).is_err());
        assert_eq!(load(&store, "record").unwrap(), Some(MAGIC.to_vec()));
        delete(&store, "record").unwrap();
        assert!(store.values.borrow().is_empty());
    }
    #[cfg(windows)]
    #[test]
    fn native_credential_manager_roundtrip() {
        let account = format!("storage-test-{:032x}", rand::random::<u128>());
        // Only touch this test's random namespace; never user login records.
        let result = (|| -> Result<(), StorageError> {
            WindowsEntries.write(&account, b"legacy")?;
            assert_eq!(load(&WindowsEntries, &account)?, Some(b"legacy".to_vec()));
            for size in [2560, 2561, 10000, 128] {
                save(&WindowsEntries, &account, &vec![3; size])?;
                assert_eq!(load(&WindowsEntries, &account)?, Some(vec![3; size]));
            }
            Ok(())
        })();
        delete(&WindowsEntries, &account).unwrap();
        result.unwrap();
    }
    #[test]
    fn missing_or_corrupted_chunk_is_not_an_empty_login() {
        let store = Memory::default();
        save(&store, "record", &vec![1; 7500]).unwrap();
        let chunk = store
            .values
            .borrow()
            .keys()
            .find(|k| k.as_str() != "record")
            .unwrap()
            .clone();
        let original = store.values.borrow_mut().remove(&chunk).unwrap();
        assert!(load(&store, "record").is_err());
        let mut changed = original;
        changed[0] ^= 1;
        store.values.borrow_mut().insert(chunk, changed);
        assert!(load(&store, "record").is_err());
    }
}
