#![cfg(windows)]
use nelomai_client_container::ipc::windows::private_pipe_pair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn anonymous_pipe_workers_exchange_bytes_and_drop_pending_read() {
    let (mut parent, child) = private_pipe_pair().unwrap();
    let mut child = child.into_local_io().unwrap();
    parent.write_all(b"private-fixture").await.unwrap();
    parent.flush().await.unwrap();
    let mut bytes = [0; 15];
    child.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"private-fixture");
    drop(parent);
    let mut byte = [0];
    assert_eq!(child.read(&mut byte).await.unwrap(), 0);
    drop(child);
}

#[test]
fn dropping_idle_pipe_workers_joins_them_without_abandoned_blocking_reader() {
    for _ in 0..20 {
        let (parent, child) = private_pipe_pair().unwrap();
        drop(parent);
        drop(child);
    }
}

#[test]
fn noninheritable_child_handles_stay_private_before_spawn() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
    let (parent, child) =
        nelomai_client_container::ipc::windows::noninheritable_pipe_pair().unwrap();
    for handle in child.handles() {
        let mut flags = 0;
        assert_ne!(
            unsafe { GetHandleInformation(handle.as_raw_handle(), &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
    }
    drop((parent, child));
}

#[test]
fn blocking_native_timeout_cancels_workers_and_poisoned_endpoint_cannot_be_reused() {
    use nelomai_client_container::desktop::NativeStream;
    use std::{
        io::Read,
        time::{Duration, Instant},
    };
    let (parent, child) = private_pipe_pair().unwrap();
    let mut stream = NativeStream::from_private_pipe(parent);
    assert!(stream.set_read_timeout(Some(Duration::ZERO)).is_err());
    stream
        .set_read_timeout(Some(Duration::from_millis(30)))
        .unwrap();
    let start = Instant::now();
    assert_eq!(
        stream.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(
        stream.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    drop(child);
}
