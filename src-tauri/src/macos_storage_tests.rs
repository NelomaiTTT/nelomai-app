use super::*;
use std::sync::Mutex;

#[derive(Clone, Default)]
struct MemoryRecord(Arc<Mutex<Option<Vec<u8>>>>);
impl ProtectedRecordStore for MemoryRecord {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(bytes.to_vec());
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

#[test]
fn runtime_reads_and_writes_only_common_owned_admitted_records() {
    let record = MemoryRecord::default();
    let (server, client) = UnixStream::pair().unwrap();
    let owner = record.clone();
    let thread = std::thread::spawn(move || serve(server, vec![owner]));
    let client = Arc::new(StorageClient::new(client).unwrap());
    let remote = RemoteRecord::new(client.clone(), 0);
    assert_eq!(remote.load_record().unwrap(), None);
    let bytes = vec![37; 200_000]; // larger than auth/native control frames
    remote.save_record(&bytes).unwrap();
    assert_eq!(record.0.lock().unwrap().as_deref(), Some(bytes.as_slice()));
    assert_eq!(remote.load_record().unwrap(), Some(bytes));
    remote.delete_record().unwrap();
    assert_eq!(remote.load_record().unwrap(), None);
    assert!(RemoteRecord::new(client.clone(), 1).load_record().is_err());
    drop((remote, client));
    thread.join().unwrap();
}

#[test]
fn closed_storage_is_an_error_not_an_empty_record() {
    let (server, client) = UnixStream::pair().unwrap();
    let remote = RemoteRecord::new(Arc::new(StorageClient::new(client).unwrap()), 0);
    drop(server);
    assert!(remote.load_record().is_err());
    assert!(remote.save_record(b"state").is_err());
}

#[test]
fn transferred_endpoint_is_private_and_close_on_exec() {
    use std::os::fd::AsRawFd;
    let (mut a, mut b) = UnixStream::pair().unwrap();
    let (server, mut client) = UnixStream::pair().unwrap();
    send_endpoint(&mut a, &server).unwrap();
    drop(server);
    let mut received = receive_endpoint(&mut b).unwrap();
    assert_ne!(
        unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    client.write_all(b"hello").unwrap();
    let mut value = [0; 5];
    received.read_exact(&mut value).unwrap();
    assert_eq!(&value, b"hello");
}

#[test]
fn temporary_backend_failure_can_be_retried_without_restart() {
    struct FailsOnce(std::sync::atomic::AtomicBool, MemoryRecord);
    impl ProtectedRecordStore for FailsOnce {
        fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
            if self.0.swap(false, std::sync::atomic::Ordering::SeqCst) {
                Err(failed().into())
            } else {
                self.1.load_record()
            }
        }
        fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
            self.1.save_record(bytes)
        }
        fn delete_record(&self) -> Result<(), StorageError> {
            self.1.delete_record()
        }
    }
    let (server, client) = UnixStream::pair().unwrap();
    let thread = std::thread::spawn(move || {
        serve(
            server,
            vec![FailsOnce(true.into(), MemoryRecord::default())],
        )
    });
    let remote = RemoteRecord::new(Arc::new(StorageClient::new(client).unwrap()), 0);
    assert!(remote.load_record().is_err());
    remote.save_record(b"retained state").unwrap();
    assert_eq!(
        remote.load_record().unwrap().as_deref(),
        Some(&b"retained state"[..])
    );
    remote.delete_record().unwrap();
    assert_eq!(remote.load_record().unwrap(), None);
    drop(remote);
    thread.join().unwrap();
}

#[test]
fn oversized_write_is_rejected_without_losing_existing_record() {
    let record = MemoryRecord::default();
    record.save_record(b"existing").unwrap();
    let (server, client) = UnixStream::pair().unwrap();
    let thread = std::thread::spawn(move || serve(server, vec![record]));
    let remote = RemoteRecord::new(Arc::new(StorageClient::new(client).unwrap()), 0);
    assert!(remote.save_record(&vec![0; MAX_FRAME]).is_err());
    assert_eq!(
        remote.load_record().unwrap().as_deref(),
        Some(&b"existing"[..])
    );
    drop(remote);
    thread.join().unwrap();
}

#[test]
fn malformed_frame_is_rejected_before_allocation() {
    for size in [0, MAX_FRAME as u32 + 1, u32::MAX] {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(&size.to_le_bytes()).unwrap();
        assert!(read_frame(&mut server).is_err());
    }
}
