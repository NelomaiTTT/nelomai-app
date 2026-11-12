#![cfg(any(target_os = "macos", target_os = "linux", windows))]

use nelomai_client_api::ClientApi;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const BODY: &[u8] = br#"{"report_id":"93778400-6408-4c6e-8275-1800972f3537","trigger":"manual","application_log":"snapshot"}"#;
const CODE: &str = "nld_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

async fn request(listener: &TcpListener) -> (TcpStream, String, Vec<u8>) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut bytes = Vec::new();
    let (headers, offset, length) = loop {
        let mut chunk = [0; 512];
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(offset) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
            let headers = String::from_utf8(bytes[..offset].to_vec()).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|s| s.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            break (headers, offset + 4, length);
        }
    };
    if bytes.len() < offset + length {
        let n = bytes.len();
        bytes.resize(offset + length, 0);
        socket.read_exact(&mut bytes[n..]).await.unwrap();
    }
    (socket, headers, bytes[offset..offset + length].to_vec())
}

#[tokio::test]
async fn support_diagnostics_posts_frozen_bytes_and_code_without_account_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, headers, body) = request(&listener).await;
        assert!(headers.starts_with("POST /api/client/v1/diagnostics/support HTTP/1.1"));
        assert!(headers.to_ascii_lowercase().contains(&format!(
            "x-nelomai-diagnostics-code: {}",
            CODE.to_ascii_lowercase()
        )));
        assert!(!headers.to_ascii_lowercase().contains("authorization:"));
        assert!(!headers.to_ascii_lowercase().contains("cookie:"));
        assert_eq!(body, BODY);
        let reply = br#"{"api_version":"1","request_id":"support-reply","report_id":"93778400-6408-4c6e-8275-1800972f3537","received_bytes":109}"#;
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len()).as_bytes()).await.unwrap();
        socket.write_all(reply).await.unwrap();
    });
    let response = client
        .upload_support_diagnostics(BODY, Some(CODE))
        .await
        .unwrap();
    assert_eq!(response.report_id, "93778400-6408-4c6e-8275-1800972f3537");
    server.await.unwrap();
}

#[tokio::test]
async fn support_diagnostics_does_not_replay_a_post_after_request_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let server = tokio::spawn(async move {
        let (socket, headers, body) = request(&listener).await;
        assert!(!headers
            .to_ascii_lowercase()
            .contains("x-nelomai-diagnostics-code:"));
        assert_eq!(body, BODY);
        drop(socket);
        assert!(
            tokio::time::timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err()
        );
    });
    assert!(client.upload_support_diagnostics(BODY, None).await.is_err());
    server.await.unwrap();
}
