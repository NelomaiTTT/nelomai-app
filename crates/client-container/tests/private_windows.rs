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
