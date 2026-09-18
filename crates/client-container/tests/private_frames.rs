use nelomai_client_container::ipc::{
    read_frame, write_frame, AuthRequestV1, FrameV1, MessageV1, PrivateError,
};
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, Instant};

#[tokio::test]
async fn private_frame_rejects_announced_oversize_without_waiting_for_payload() {
    let (mut sender, mut receiver) = tokio::io::duplex(8);
    sender.write_all(&65537_u32.to_be_bytes()).await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        read_frame(&mut receiver, Instant::now() + Duration::from_secs(10)),
    )
    .await;
    assert!(result.unwrap().is_err());
}

#[tokio::test]
async fn private_frame_rejects_truncation_and_wrong_version() {
    for bytes in [vec![0, 0], vec![0, 0, 0, 4, b'{']] {
        let (mut sender, mut receiver) = tokio::io::duplex(256);
        sender.write_all(&bytes).await.unwrap();
        drop(sender);
        assert!(
            read_frame(&mut receiver, Instant::now() + Duration::from_secs(10))
                .await
                .is_err()
        );
    }
    let (mut sender, mut receiver) = tokio::io::duplex(4096);
    let mut frame = FrameV1::new(1, MessageV1::Request(AuthRequestV1::State));
    frame.version = 2;
    let deadline = Instant::now() + Duration::from_secs(10);
    write_frame(&mut sender, frame, deadline).await.unwrap();
    assert!(matches!(
        read_frame(&mut receiver, deadline).await,
        Err(PrivateError::Protocol)
    ));
}

#[tokio::test(start_paused = true)]
async fn private_frame_uses_one_deadline_across_header_and_payload() {
    let (mut sender, mut receiver) = tokio::io::duplex(8);
    let start = Instant::now();
    let task =
        tokio::spawn(
            async move { read_frame(&mut receiver, start + Duration::from_secs(10)).await },
        );
    tokio::time::sleep(Duration::from_secs(9)).await;
    sender.write_all(&100_u32.to_be_bytes()).await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert_eq!(start.elapsed(), Duration::from_secs(10));
}

#[tokio::test]
async fn private_frame_roundtrip_and_debug_never_print_password() {
    let frame = FrameV1::new(
        7,
        MessageV1::Request(AuthRequestV1::Login {
            stamp: None,
            request: nelomai_client_api::RuntimeLogin {
                login: "private-login".into(),
                password: "private-password".into(),
                device_name: "fixture".into(),
            },
        }),
    );
    assert!(!format!("{frame:?}").contains("private-password"));
    let (mut sender, mut receiver) = tokio::io::duplex(4096);
    let deadline = Instant::now() + Duration::from_secs(10);
    write_frame(&mut sender, frame, deadline).await.unwrap();
    let received = read_frame(&mut receiver, deadline).await.unwrap();
    assert_eq!(received.id, 7);
    assert!(matches!(
        received.message,
        MessageV1::Request(AuthRequestV1::Login { .. })
    ));
}
