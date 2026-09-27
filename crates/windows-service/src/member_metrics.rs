//! Scoped peer telemetry decoders. Input belongs to one already-authorized native
//! adapter/pipe; its transport counters are NOT independent decrypted progress.

use nelomai_client_tunnel::TunnelMetrics;
use std::io;

pub const MAX_METRICS_BYTES: usize = 1024 * 1024;

// Deliberately no Debug: the native configuration includes private keys.
pub struct SecretNtConfiguration {
    words: zeroize::Zeroizing<Vec<u64>>,
    length: usize,
}
impl SecretNtConfiguration {
    pub fn bytes(&self) -> &[u8] {
        // length is checked against the allocated byte capacity before creation.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }
}

/// Bounded WireGuardNT GetConfiguration sizing/read sequence. `false` means
/// ERROR_MORE_DATA only; every other native error must propagate as Err. An empty
/// slice is the initial null-buffer sizing query. Buffers are ABI-aligned and
/// wiped before release even when the adapter changes size or the read fails.
pub fn query_wireguard_nt(
    mut read: impl FnMut(&mut [u64], &mut u32) -> io::Result<bool>,
) -> io::Result<SecretNtConfiguration> {
    let mut length = 0;
    if read(&mut [], &mut length)? {
        return Err(invalid());
    }
    for _ in 0..3 {
        let capacity = length as usize;
        if !(216..=MAX_METRICS_BYTES).contains(&capacity) {
            return Err(invalid());
        }
        let mut words = zeroize::Zeroizing::new(vec![0u64; capacity.div_ceil(8)]);
        if read(&mut words, &mut length)? {
            if length as usize > capacity || length < 216 {
                return Err(invalid());
            }
            return Ok(SecretNtConfiguration {
                words,
                length: length as usize,
            });
        }
        if length as usize <= capacity {
            return Err(invalid());
        }
    }
    Err(invalid())
}

/// One read-only UAPI transaction. The stream must already be bound to the
/// authenticated service instance. Nonblocking I/O is cancelled at the deadline;
/// unlike a timed-out blocking worker it cannot retain the pipe indefinitely.
/// The result contains keys: decode it immediately, never format/log it.
pub async fn query_awg_uapi<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    deadline: std::time::Duration,
) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(deadline, async {
        stream.write_all(b"get=1\n\n").await?;
        // Reserve the entire upper bound so realloc cannot leave secret copies.
        let mut result = zeroize::Zeroizing::new(Vec::with_capacity(MAX_METRICS_BYTES));
        let mut chunk = zeroize::Zeroizing::new([0u8; 4096]);
        loop {
            let length = stream.read(&mut chunk[..]).await?;
            if length == 0 || result.len() + length > MAX_METRICS_BYTES {
                return Err(invalid());
            }
            let previous = result.len();
            result.extend_from_slice(&chunk[..length]);
            if let Some(end) = result[previous.saturating_sub(1)..]
                .windows(2)
                .position(|w| w == b"\n\n")
            {
                if previous.saturating_sub(1) + end + 2 != result.len() {
                    return Err(invalid());
                }
                return Ok(result);
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "member_metrics_timeout"))?
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "member_metrics_unconfirmed")
}
fn timestamp(value: Option<u64>, started: u64, now: u64) -> io::Result<Option<u64>> {
    if started > now || value.is_some_and(|v| v > now) {
        return Err(invalid());
    }
    Ok(value.filter(|v| *v >= started))
}
fn metrics(
    tx: u64,
    rx: u64,
    handshake: Option<u64>,
    started: u64,
    now: u64,
) -> io::Result<TunnelMetrics> {
    Ok(TunnelMetrics {
        sent_bytes: tx,
        received_bytes: rx,
        latest_handshake_epoch_millis: timestamp(handshake, started, now)?,
        probe_target: None,
    })
}

/// WireGuardNT1.1 ABI: aligned interface80, peer136, allowed-IP24. Bounded byte
/// reads avoid unaligned Rust references. Caller zeroizes the secret-bearing
/// GetConfiguration buffer after this returns (including error paths).
pub fn decode_wireguard_nt(
    bytes: &[u8],
    peer: &[u8; 32],
    started: u64,
    now: u64,
) -> io::Result<TunnelMetrics> {
    if bytes.len() < 216 || bytes.len() > MAX_METRICS_BYTES {
        return Err(invalid());
    }
    let u32_at = |offset: usize| {
        u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("bounded header"),
        )
    };
    let u64_at = |offset: usize| {
        u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("bounded header"),
        )
    };
    if u32_at(72) != 1 || u32_at(80) & 1 == 0 || &bytes[88..120] != peer {
        return Err(invalid());
    }
    let allowed = u32_at(208) as usize;
    if allowed > 16384 || bytes.len() != 216 + allowed * 24 {
        return Err(invalid());
    }
    let ticks = u64_at(200);
    let handshake = if ticks == 0 {
        None
    } else {
        Some(
            ticks
                .checked_sub(116_444_736_000_000_000)
                .ok_or_else(invalid)?
                / 10_000,
        )
    };
    metrics(u64_at(184), u64_at(192), handshake, started, now)
}

/// UAPI get response from the exact owned AmneziaWG pipe. Only a complete single
/// expected peer can publish observations. Never fall back to global ringlogger.
pub fn decode_awg_uapi(
    bytes: &[u8],
    peer: &[u8; 32],
    started: u64,
    now: u64,
) -> io::Result<TunnelMetrics> {
    if bytes.len() > MAX_METRICS_BYTES {
        return Err(invalid());
    }
    let body = std::str::from_utf8(bytes)
        .map_err(|_| invalid())?
        .strip_suffix("errno=0\n\n")
        .ok_or_else(invalid)?;
    let (mut found, mut tx, mut rx, mut sec, mut ns) = (false, None, None, None, None);
    for line in body.lines() {
        let (key, value) = line.split_once('=').ok_or_else(invalid)?;
        if key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || value.contains(['\r', '\0'])
        {
            return Err(invalid());
        }
        match key {
            "public_key" => {
                if found || value.len() != 64 {
                    return Err(invalid());
                }
                for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
                    let hex = |b: u8| match b {
                        b'0'..=b'9' => Some(b - b'0'),
                        b'a'..=b'f' => Some(b - b'a' + 10),
                        b'A'..=b'F' => Some(b - b'A' + 10),
                        _ => None,
                    };
                    if (hex(pair[0]).ok_or_else(invalid)? << 4
                        | hex(pair[1]).ok_or_else(invalid)?)
                        != peer[index]
                    {
                        return Err(invalid());
                    }
                }
                found = true;
            }
            "tx_bytes" | "rx_bytes" | "last_handshake_time_sec" | "last_handshake_time_nsec" => {
                if !found || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid());
                }
                let number = value.parse::<u64>().map_err(|_| invalid())?;
                let field = match key {
                    "tx_bytes" => &mut tx,
                    "rx_bytes" => &mut rx,
                    "last_handshake_time_sec" => &mut sec,
                    _ => &mut ns,
                };
                if field.replace(number).is_some() {
                    return Err(invalid());
                }
            }
            "errno" => return Err(invalid()),
            _ => {} // Native keys/endpoint/AllowedIPs/AWG fields are not telemetry.
        }
    }
    if !found {
        return Err(invalid());
    }
    let (seconds, nanos) = (sec.ok_or_else(invalid)?, ns.ok_or_else(invalid)?);
    if nanos >= 1_000_000_000 || seconds == 0 && nanos != 0 {
        return Err(invalid());
    }
    let handshake = if seconds == 0 {
        None
    } else {
        Some(
            seconds
                .checked_mul(1000)
                .and_then(|s| s.checked_add(nanos / 1_000_000))
                .ok_or_else(invalid)?,
        )
    };
    metrics(
        tx.ok_or_else(invalid)?,
        rx.ok_or_else(invalid)?,
        handshake,
        started,
        now,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const PEER: [u8; 32] = [7; 32];
    fn nt(handshake: u64) -> Vec<u8> {
        let mut bytes = vec![0; 240]; //80 interface +136 peer +24 allowed IP
        bytes[72..76].copy_from_slice(&1u32.to_le_bytes());
        bytes[80..84].copy_from_slice(&1u32.to_le_bytes());
        bytes[88..120].copy_from_slice(&PEER);
        bytes[184..192].copy_from_slice(&1234u64.to_le_bytes());
        bytes[192..200].copy_from_slice(&5678u64.to_le_bytes());
        bytes[200..208].copy_from_slice(&handshake.to_le_bytes());
        bytes[208..212].copy_from_slice(&1u32.to_le_bytes());
        bytes
    }
    fn uapi(seconds: &str, nanos: &str) -> String {
        format!("private_key={}\nlisten_port=50000\npublic_key={}\npreshared_key={}\nlast_handshake_time_sec={seconds}\nlast_handshake_time_nsec={nanos}\ntx_bytes=1234\nrx_bytes=5678\nallowed_ip=0.0.0.0/0\nerrno=0\n\n","aa".repeat(32),"07".repeat(32),"bb".repeat(32))
    }
    #[test]
    fn wireguard_nt_reads_only_expected_peer_and_converts_filetime() {
        let metrics = decode_wireguard_nt(
            &nt(116444736000000000 + 1_700_000_000_123 * 10_000),
            &PEER,
            1_700_000_000_000,
            1_700_000_000_999,
        )
        .unwrap();
        assert_eq!(metrics.sent_bytes, 1234);
        assert_eq!(metrics.received_bytes, 5678);
        assert_eq!(
            metrics.latest_handshake_epoch_millis,
            Some(1_700_000_000_123)
        );
    }
    #[test]
    fn nt_rejects_other_peer_truncation_multiple_peers_and_trailing_data() {
        assert!(decode_wireguard_nt(&nt(0), &[8; 32], 0, 100).is_err());
        for length in [0, 79, 80, 215, 239] {
            assert!(decode_wireguard_nt(&nt(0)[..length], &PEER, 0, 100).is_err());
        }
        let mut bytes = nt(0);
        bytes[72..76].copy_from_slice(&2u32.to_le_bytes());
        assert!(decode_wireguard_nt(&bytes, &PEER, 0, 100).is_err());
        let mut bytes = nt(0);
        bytes.push(0);
        assert!(decode_wireguard_nt(&bytes, &PEER, 0, 100).is_err());
    }
    #[test]
    fn old_handshake_never_validates_new_start_and_future_timestamp_is_rejected() {
        for tick in [0, 116444736000000000 + 1000 * 10_000] {
            assert_eq!(
                decode_wireguard_nt(&nt(tick), &PEER, 2000, 3000)
                    .unwrap()
                    .latest_handshake_epoch_millis,
                None
            );
        }
        assert!(
            decode_wireguard_nt(&nt(116444736000000000 + 4000 * 10_000), &PEER, 2000, 3000)
                .is_err()
        );
        assert!(decode_wireguard_nt(&nt(1), &PEER, 0, 3000).is_err());
    }
    #[test]
    fn awg_metrics_require_terminal_success_and_exact_peer() {
        let text = uapi("1700000000", "123000000");
        let metrics =
            decode_awg_uapi(text.as_bytes(), &PEER, 1_700_000_000_000, 1_700_000_000_999).unwrap();
        assert_eq!(
            metrics.latest_handshake_epoch_millis,
            Some(1_700_000_000_123)
        );
        assert_eq!((metrics.sent_bytes, metrics.received_bytes), (1234, 5678));
        assert!(decode_awg_uapi(text.as_bytes(), &[8; 32], 0, u64::MAX).is_err());
        for malformed in [
            text.replace("errno=0", "errno=5"),
            text.trim_end().to_string(),
            text.replace("rx_bytes=5678\n", ""),
            text.replace("tx_bytes=1234", "tx_bytes=1234\ntx_bytes=12"),
            format!("{text}rx_bytes=9999\n"),
        ] {
            assert!(decode_awg_uapi(malformed.as_bytes(), &PEER, 0, u64::MAX).is_err());
        }
    }
    #[test]
    fn awg_invalid_timestamps_and_extra_peer_never_merge_counters() {
        for (sec, nsec) in [
            ("1", "1000000000"),
            ("18446744073709551615", "0"),
            ("0", "1"),
            ("-1", "0"),
        ] {
            assert!(decode_awg_uapi(uapi(sec, nsec).as_bytes(), &PEER, 0, u64::MAX).is_err());
        }
        let text = uapi("0", "0").replace(
            "errno=0",
            &format!("public_key={}\nerrno=0", "07".repeat(32)),
        );
        assert!(decode_awg_uapi(text.as_bytes(), &PEER, 0, 100).is_err());
    }
    #[test]
    fn diagnostic_error_never_contains_configuration_secrets() {
        let error = decode_awg_uapi(b"private_key=do-not-print\n\n", &PEER, 0, 100).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("do-not-print"));
    }

    #[test]
    fn nt_query_retries_bounded_growth_and_keeps_aligned_zeroed_buffers() {
        let mut calls = 0;
        let data = query_wireguard_nt(|words, length| {
            calls += 1;
            assert!(words.iter().all(|word| *word == 0));
            assert_eq!(words.as_ptr() as usize % 8, 0);
            match calls {
                1 => {
                    assert!(words.is_empty());
                    *length = 216;
                    Ok(false)
                }
                2 => {
                    words[0] = 123;
                    *length = 240;
                    Ok(false)
                }
                3 => {
                    assert_eq!(words.len(), 30);
                    words[0] = 456;
                    *length = 240;
                    Ok(true)
                }
                _ => panic!("unbounded retry"),
            }
        })
        .unwrap();
        assert_eq!(data.bytes().len(), 240);
        assert_eq!(&data.bytes()[..8], &456u64.to_ne_bytes());
        assert_eq!(calls, 3);
    }

    #[test]
    fn nt_query_rejects_oversize_nonprogress_and_inconsistent_success() {
        for size in [0, 80, 215, MAX_METRICS_BYTES as u32 + 1, u32::MAX] {
            let mut calls = 0;
            assert!(query_wireguard_nt(|_, length| {
                calls += 1;
                *length = size;
                Ok(false)
            })
            .is_err());
            assert_eq!(calls, 1);
        }
        for success in [false, true] {
            assert!(query_wireguard_nt(|words, length| {
                if words.is_empty() {
                    *length = 216;
                    Ok(false)
                } else {
                    if success {
                        *length = 240;
                    }
                    Ok(success)
                }
            })
            .is_err());
        }
        let mut calls = 0;
        assert!(query_wireguard_nt(|_, length| {
            calls += 1;
            *length = 216 + calls * 24;
            Ok(false)
        })
        .is_err());
        assert_eq!(calls, 4); // one sizing call plus at most three reads
    }

    #[tokio::test]
    async fn uapi_exchange_handles_fragments_without_waiting_for_pipe_close() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move {
            let mut command = [0; 7];
            server.read_exact(&mut command).await.unwrap();
            assert_eq!(&command, b"get=1\n\n");
            for part in [b"errno=".as_slice(), b"0\n", b"\n"] {
                server.write_all(part).await.unwrap();
                tokio::task::yield_now().await;
            }
            server
        });
        let response = query_awg_uapi(&mut client, std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(&response[..], b"errno=0\n\n");
        let _still_open = server_task.await.unwrap();
    }

    #[tokio::test]
    async fn uapi_exchange_rejects_incomplete_eof_and_times_out_stalled_peer() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let writer = tokio::spawn(async move {
            server.write_all(b"private_key=secret\n").await.unwrap();
        });
        assert!(
            query_awg_uapi(&mut client, std::time::Duration::from_secs(1))
                .await
                .is_err()
        );
        writer.await.unwrap();
        let (mut client, _server) = tokio::io::duplex(128);
        assert_eq!(
            query_awg_uapi(&mut client, std::time::Duration::from_millis(10))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn uapi_exchange_is_bounded_and_rejects_trailing_second_response() {
        for payload in [
            vec![b'x'; MAX_METRICS_BYTES + 1],
            b"errno=0\n\nextra=secret\n".to_vec(),
        ] {
            let (mut client, mut server) = tokio::io::duplex(MAX_METRICS_BYTES + 100);
            server.write_all(&payload).await.unwrap();
            assert!(
                query_awg_uapi(&mut client, std::time::Duration::from_secs(1))
                    .await
                    .is_err()
            );
        }
    }
}
