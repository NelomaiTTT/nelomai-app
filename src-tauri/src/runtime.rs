//! Versioned desktop product process: UI, recovery and runtime records. Common
//! auth, installation, update and process authority are reached only privately.
use crate::*;
#[cfg(target_os = "macos")]
use nelomai_client_container::desktop::{NATIVE_STALL_REBIND, NATIVE_WAKE_MUTATION};
use nelomai_client_container::{
    desktop::{read_native_frame, write_native_frame},
    host::RuntimeBootstrapV1,
    ipc::{ChildAdmission, PrivateRuntimeAuthClient, RuntimeRecordInventory},
};
#[cfg(target_os = "macos")]
use nelomai_client_tunnel::{StallRebindGuard, WakeDispatchGuard};
use serde::{Deserialize, Serialize};
use std::{
    io,
    sync::{Mutex as StdMutex, OnceLock},
};
use tauri::Manager;

#[cfg(unix)]
type NativeStream = std::os::unix::net::UnixStream;
#[cfg(unix)]
type AuthStream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type NativeStream = nelomai_client_container::desktop::NativeStream;
#[cfg(windows)]
type AuthStream = nelomai_client_container::ipc::windows::PrivatePipeIo;
static NATIVE: OnceLock<Arc<NativeClient>> = OnceLock::new();
#[cfg(target_os = "macos")]
static STORAGE: OnceLock<Arc<crate::macos_storage::StorageClient>> = OnceLock::new();

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraySnapshot {
    pub disconnect: bool,
    pub traffic: String,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeAction {
    Show,
    Toggle,
    Quit,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeExitReason {
    Shutdown,
    Update,
    RuntimeSwitch,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum NativeControl {
    #[cfg(target_os = "macos")]
    OpenStorage,
    Prepare,
    Poll {
        presentation: TraySnapshot,
    },
    Exit {
        reason: NativeExitReason,
    },
    #[cfg(windows)]
    DefenderStatus {
        refresh: bool,
    },
    #[cfg(windows)]
    DefenderRepair,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum NativeReply {
    Done,
    Actions {
        actions: Vec<RuntimeAction>,
    },
    #[cfg(windows)]
    Defender {
        status: nelomai_windows_service::DefenderStatus,
    },
}
pub(crate) struct NativeClient {
    stream: Arc<StdMutex<Option<NativeStream>>>,
}
impl NativeClient {
    pub(crate) fn new(stream: NativeStream) -> io::Result<Self> {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        Ok(Self {
            stream: Arc::new(StdMutex::new(Some(stream))),
        })
    }
    pub async fn exchange(&self, tag: u8, body: Vec<u8>) -> io::Result<Vec<u8>> {
        self.exchange_frame(tag, move |stream| {
            // Engine requests have the existing 40s native watchdog. Installer
            // authorization has its existing 120s bound; auth IPC stays 10s.
            let installation =
                serde_json::from_slice::<NativeControl>(&body).is_ok_and(|request| match request {
                    NativeControl::Prepare => true,
                    #[cfg(windows)]
                    NativeControl::DefenderRepair => true,
                    _ => false,
                });
            let timeout = if tag == 1 {
                45
            } else if installation {
                130
            } else {
                10
            };
            stream.set_read_timeout(Some(Duration::from_secs(timeout)))?;
            write_native_frame(stream, tag, &body)?;
            Ok(true)
        })
        .await
    }
    #[cfg(target_os = "macos")]
    async fn exchange_stall_rebind(&self, guard: StallRebindGuard) -> io::Result<Vec<u8>> {
        use std::time::Instant;

        let now = uptime_nanos()?;
        let remaining = guard.deadline().saturating_duration_since(Instant::now());
        let deadline = u64::try_from(remaining.as_nanos())
            .ok()
            .and_then(|nanos| now.checked_add(nanos))
            .ok_or_else(|| io::Error::other("invalid stall rebind deadline"))?;
        let mut body = deadline.to_le_bytes().to_vec();
        let wake = guard.wake().map(WakeDispatchGuard::wake_stamp);
        if let Some(stamp) = wake {
            body.extend_from_slice(&stamp.unwrap_or(0).to_le_bytes());
        }
        self.exchange_guarded_frame(NATIVE_STALL_REBIND, body, None, move || {
            guard.is_current()
                && wake.is_none_or(crate::macos_power::dispatch_wake_is_current)
                && uptime_nanos().is_ok_and(|now| now < deadline)
        })
        .await
    }

    #[cfg(target_os = "macos")]
    async fn exchange_wake_mutation(
        &self,
        request: nelomai_unix_service::Request,
        mut guard: WakeDispatchGuard,
    ) -> io::Result<Vec<u8>> {
        let revoked = guard.take_cancellation();
        let wake_stamp = guard.wake_stamp();
        let mut body = wake_stamp.unwrap_or(0).to_le_bytes().to_vec();
        let deadline = match guard.uptime_deadline() {
            Some(time) => u64::try_from(time.as_nanos()).map_err(|_| io::ErrorKind::InvalidData)?,
            None => u64::MAX,
        };
        body.extend_from_slice(&deadline.to_le_bytes());
        serde_json::to_writer(&mut body, &request)?;
        self.exchange_guarded_frame(NATIVE_WAKE_MUTATION, body, revoked, move || {
            guard.is_current() && wake_dispatch_is_current(wake_stamp, deadline)
        })
        .await
    }

    #[cfg(target_os = "macos")]
    async fn exchange_guarded_frame(
        &self,
        tag: u8,
        body: Vec<u8>,
        revoked: Option<nelomai_client_tunnel::DispatchCancellation>,
        can_dispatch: impl FnOnce() -> bool + Send + 'static,
    ) -> io::Result<Vec<u8>> {
        let (lifetime, peer) = NativeStream::pair()?;
        let exchange = self.exchange_frame(tag, move |stream| {
            stream.set_read_timeout(Some(Duration::from_secs(45)))?;
            if !can_dispatch() || !native_guard_peer_open(&peer) {
                return Ok(false);
            }
            write_native_frame(stream, tag, &body)?;
            crate::macos_storage::send_endpoint(stream, &peer)?;
            Ok(true)
        });
        tokio::pin!(exchange);
        if let Some(revoked) = revoked {
            tokio::select! {
                biased;
                _ = revoked => drop(lifetime),
                reply = &mut exchange => return reply,
            }
        }
        // Closing the peer fences pending writes. A mutation accepted earlier
        // still returns its receipt to the owner for durable cleanup.
        exchange.await
    }

    async fn exchange_frame(
        &self,
        tag: u8,
        write: impl FnOnce(&mut NativeStream) -> io::Result<bool> + Send + 'static,
    ) -> io::Result<Vec<u8>> {
        let stream = self.stream.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let mut channel = stream
                .lock()
                .map_err(|_| io::Error::other("common channel unavailable"))?;
            let stream = channel
                .as_mut()
                .ok_or_else(|| io::Error::other("common channel closed"))?;
            // A guarded writer may decline before emitting any bytes. In
            // that case the inherited stream stays aligned for its next call.
            let result = write(stream)
                .and_then(|written| written.then(|| read_native_frame(stream)).transpose());
            let (reply, body) = match result {
                Ok(Some(reply)) => reply,
                Ok(None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        NativeDispatchDeferred,
                    ));
                }
                Err(error) => {
                    *channel = None;
                    return Err(error);
                }
            };
            if reply != tag && reply != 255 {
                *channel = None;
            }
            if reply != tag {
                return Err(io::Error::other("common operation failed"));
            }
            Ok(body)
        })
        .await
        .map_err(|_| io::Error::other("common channel unavailable"))?
    }
    pub async fn control(&self, request: NativeControl) -> io::Result<NativeReply> {
        let body = self.exchange(2, serde_json::to_vec(&request)?).await?;
        serde_json::from_slice(&body).map_err(Into::into)
    }
}

#[cfg(target_os = "macos")]
fn uptime_nanos() -> io::Result<u64> {
    // Use a host-wide monotonic clock that includes suspend. A duration sent
    // on the wire would extend the deadline by the time this waited in IPC.
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
}

#[derive(Debug)]
struct NativeDispatchDeferred;

impl std::fmt::Display for NativeDispatchDeferred {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native dispatch deferred")
    }
}

impl std::error::Error for NativeDispatchDeferred {}

#[cfg(target_os = "macos")]
fn native_guard_peer_open(peer: &NativeStream) -> bool {
    use std::os::fd::AsRawFd;

    let mut byte: u8 = 0;
    let result = unsafe {
        libc::recv(
            peer.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    // The socket carries no payload. An unexpected byte, EOF, or any error
    // other than "would block" is cancellation.
    result == -1 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock
}

#[cfg(target_os = "macos")]
pub(crate) fn stall_rebind_guard(body: &[u8], peer: NativeStream) -> io::Result<StallRebindGuard> {
    use std::time::Instant;

    let (deadline, tail) = body
        .split_first_chunk::<8>()
        .ok_or(io::ErrorKind::InvalidData)?;
    let deadline = u64::from_le_bytes(*deadline);
    let wake = if tail.is_empty() {
        None
    } else {
        Some(decode_wake_stamp(tail)?)
    };
    let now = Instant::now();
    let remaining = deadline.saturating_sub(uptime_nanos()?);
    let local_deadline = now
        .checked_add(Duration::from_nanos(remaining))
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok(StallRebindGuard::new(local_deadline, move || {
        uptime_nanos().is_ok_and(|now| now < deadline)
            && native_guard_peer_open(&peer)
            && wake.is_none_or(crate::macos_power::dispatch_wake_is_current)
    }))
}
#[cfg(target_os = "macos")]
pub(crate) fn wake_mutation_request(
    body: &[u8],
    peer: NativeStream,
) -> io::Result<(nelomai_unix_service::Request, WakeDispatchGuard)> {
    use nelomai_unix_service::Request;

    let (stamp, request) = body
        .split_first_chunk::<{ size_of::<i64>() }>()
        .ok_or(io::ErrorKind::InvalidData)?;
    let wake_stamp = decode_wake_stamp(stamp)?;
    let (deadline, request) = request
        .split_first_chunk::<8>()
        .ok_or(io::ErrorKind::InvalidData)?;
    let deadline = u64::from_le_bytes(*deadline);
    let request: Request = serde_json::from_slice(request)?;
    if !request.allows_wake_dispatch() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let guard = WakeDispatchGuard::new(wake_stamp, move || {
        native_guard_peer_open(&peer) && wake_dispatch_is_current(wake_stamp, deadline)
    });
    Ok((request, guard))
}

#[cfg(target_os = "macos")]
fn decode_wake_stamp(bytes: &[u8]) -> io::Result<Option<i64>> {
    let stamp = i64::from_le_bytes(bytes.try_into().map_err(|_| io::ErrorKind::InvalidData)?);
    if stamp < 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok((stamp > 0).then_some(stamp))
}

#[cfg(target_os = "macos")]
fn wake_dispatch_is_current(stamp: Option<i64>, deadline: u64) -> bool {
    (deadline == u64::MAX || uptime_nanos().is_ok_and(|now| now < deadline))
        && crate::macos_power::dispatch_wake_is_current(stamp)
}

pub(crate) fn native() -> io::Result<Arc<NativeClient>> {
    NATIVE
        .get()
        .cloned()
        .ok_or_else(|| io::Error::other("private runtime startup required"))
}

#[cfg(all(test, unix))]
mod native_tests {
    use super::*;

    #[test]
    fn immutable_stable_poll_wire_format_is_unchanged() {
        let frame = serde_json::json!({
            "command": "poll",
            "presentation": {"disconnect": false, "traffic": ""}
        });
        let poll = serde_json::from_value::<NativeControl>(frame.clone()).unwrap();
        assert!(matches!(poll, NativeControl::Poll { .. }));
        assert_eq!(serde_json::to_value(poll).unwrap(), frame);
    }

    #[test]
    fn runtime_restart_is_an_explicit_full_common_exit_reason() {
        let encoded = serde_json::to_value(NativeControl::Exit {
            reason: NativeExitReason::RuntimeSwitch,
        })
        .unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({"command":"exit","reason":"runtime_switch"}),
        );
    }

    #[test]
    fn rejected_poll_preserves_channel_for_later_show_and_quit() {
        let (client, mut peer) = NativeStream::pair().unwrap();
        let client = NativeClient::new(client).unwrap();
        let worker = std::thread::spawn(move || {
            for rejected in [true, false] {
                let (tag, body) = read_native_frame(&mut peer).unwrap();
                assert_eq!(tag, 2);
                assert!(matches!(
                    serde_json::from_slice::<NativeControl>(&body).unwrap(),
                    NativeControl::Poll { .. }
                ));
                if rejected {
                    write_native_frame(&mut peer, 255, b"common operation failed").unwrap();
                } else {
                    let body = serde_json::to_vec(&NativeReply::Actions {
                        actions: vec![RuntimeAction::Show, RuntimeAction::Quit],
                    })
                    .unwrap();
                    write_native_frame(&mut peer, 2, &body).unwrap();
                }
            }
        });
        tauri::async_runtime::block_on(async {
            assert!(client
                .control(NativeControl::Poll {
                    presentation: TraySnapshot::default(),
                })
                .await
                .is_err());
            assert!(client.stream.lock().unwrap().is_some());
            let reply = client
                .control(NativeControl::Poll {
                    presentation: TraySnapshot::default(),
                })
                .await
                .unwrap();
            assert!(matches!(
                reply,
                NativeReply::Actions { actions }
                    if matches!(actions.as_slice(), [RuntimeAction::Show, RuntimeAction::Quit])
            ));
        });
        worker.join().unwrap();
    }

    #[test]
    fn closed_reply_permanently_closes_native_channel() {
        let (client, mut peer) = NativeStream::pair().unwrap();
        let client = NativeClient::new(client).unwrap();
        let worker = std::thread::spawn(move || {
            read_native_frame(&mut peer).unwrap();
        });
        assert!(
            tauri::async_runtime::block_on(client.control(NativeControl::Poll {
                presentation: TraySnapshot::default(),
            }))
            .is_err()
        );
        worker.join().unwrap();
        assert!(client.stream.lock().unwrap().is_none());
        assert!(
            tauri::async_runtime::block_on(client.control(NativeControl::Poll {
                presentation: TraySnapshot::default(),
            }))
            .is_err()
        );
    }

    #[test]
    fn malformed_reply_permanently_closes_native_channel() {
        let (client, mut peer) = NativeStream::pair().unwrap();
        let client = NativeClient::new(client).unwrap();
        let worker = std::thread::spawn(move || {
            use std::io::Write;
            read_native_frame(&mut peer).unwrap();
            peer.write_all(&[99, 0, 0, 0, 0]).unwrap();
        });
        assert!(tauri::async_runtime::block_on(client.exchange(2, b"{}".to_vec())).is_err());
        worker.join().unwrap();
        assert!(
            client.stream.lock().unwrap().is_none(),
            "a partial/invalid reply must never be reused as the next response"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cancelled_stall_rebind_queued_behind_poll_does_not_reach_common() {
        use std::time::Instant;

        let (stream, mut peer) = NativeStream::pair().unwrap();
        let client = Arc::new(NativeClient::new(stream).unwrap());
        let (poll_seen, held) = tokio::sync::oneshot::channel();
        let (release, allow_reply) = std::sync::mpsc::channel();
        let (checked, no_rebind) = tokio::sync::oneshot::channel();
        let worker = std::thread::spawn(move || {
            assert_eq!(read_native_frame(&mut peer).unwrap().0, 2);
            poll_seen.send(()).unwrap();
            allow_reply.recv_timeout(Duration::from_secs(3)).unwrap();
            let body = serde_json::to_vec(&NativeReply::Actions { actions: vec![] }).unwrap();
            write_native_frame(&mut peer, 2, &body).unwrap();

            peer.set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            let queued = read_native_frame(&mut peer);
            let escaped = if let Ok((tag, _)) = queued {
                write_native_frame(&mut peer, tag, b"{}").unwrap();
                true
            } else {
                false
            };
            checked.send(escaped).unwrap();

            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            assert_eq!(read_native_frame(&mut peer).unwrap().0, 2);
            write_native_frame(&mut peer, 2, &body).unwrap();
        });

        let escaped = tauri::async_runtime::block_on(async {
            let poll = || NativeControl::Poll {
                presentation: TraySnapshot::default(),
            };
            let initial = {
                let client = client.clone();
                tauri::async_runtime::spawn(async move { client.control(poll()).await })
            };
            held.await.unwrap();
            let guard = StallRebindGuard::new(Instant::now() + Duration::from_secs(3), || true);
            let mut rebind = Box::pin(client.exchange_stall_rebind(guard));
            tokio::select! {
                biased;
                _ = &mut rebind => panic!("stall rebind must be waiting behind the first poll"),
                _ = tokio::task::yield_now() => {}
            }
            drop(rebind);
            release.send(()).unwrap();
            initial.await.unwrap().unwrap();
            let escaped = no_rebind.await.unwrap();
            client.control(poll()).await.unwrap();
            escaped
        });
        worker.join().unwrap();
        assert!(!escaped, "cancelled stall rebind escaped the runtime queue");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn dropping_runtime_stall_rebind_invalidates_the_forwarded_guard() {
        use std::time::Instant;

        let (stream, mut peer) = NativeStream::pair().unwrap();
        let client = NativeClient::new(stream).unwrap();
        let (guard_seen, received) = tokio::sync::oneshot::channel();
        let (cancelled, wait_for_cancellation) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let (tag, body) = read_native_frame(&mut peer).unwrap();
            assert_eq!(tag, NATIVE_STALL_REBIND);
            let endpoint = crate::macos_storage::receive_endpoint(&mut peer).unwrap();
            let guard = stall_rebind_guard(&body, endpoint).unwrap();
            assert!(guard.is_current());
            guard_seen.send(()).unwrap();
            wait_for_cancellation
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            assert!(
                !guard.is_current(),
                "forwarded guard must see Runtime future drop"
            );
            write_native_frame(&mut peer, 255, b"common operation failed").unwrap();

            // The blocking worker drains its own cancellation response and
            // a following control exchange still uses the inherited stream.
            assert_eq!(read_native_frame(&mut peer).unwrap().0, 2);
            let body = serde_json::to_vec(&NativeReply::Actions { actions: vec![] }).unwrap();
            write_native_frame(&mut peer, 2, &body).unwrap();
        });
        tauri::async_runtime::block_on(async {
            let guard = StallRebindGuard::new(Instant::now() + Duration::from_secs(3), || true);
            let mut rebind = Box::pin(client.exchange_stall_rebind(guard));
            tokio::select! {
                outcome = &mut rebind => panic!("stall rebind must wait for Common: {outcome:?}"),
                result = received => result.unwrap(),
            }
            drop(rebind);
            cancelled.send(()).unwrap();
            client
                .control(NativeControl::Poll {
                    presentation: TraySnapshot::default(),
                })
                .await
                .unwrap();
        });
        worker.join().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn revoked_stall_start_queued_behind_poll_never_reaches_common() {
        use nelomai_unix_service::Request;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (stream, mut peer) = NativeStream::pair().unwrap();
        let client = Arc::new(NativeClient::new(stream).unwrap());
        let (poll_seen, held) = tokio::sync::oneshot::channel();
        let (release, allow_reply) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            assert_eq!(read_native_frame(&mut peer).unwrap().0, 2);
            poll_seen.send(()).unwrap();
            allow_reply.recv_timeout(Duration::from_secs(3)).unwrap();
            let body = serde_json::to_vec(&NativeReply::Actions { actions: vec![] }).unwrap();
            write_native_frame(&mut peer, 2, &body).unwrap();

            let (tag, _) = read_native_frame(&mut peer).unwrap();
            if tag == NATIVE_WAKE_MUTATION {
                crate::macos_storage::receive_endpoint(&mut peer).unwrap();
                write_native_frame(&mut peer, tag, b"{}").unwrap();
            } else {
                write_native_frame(&mut peer, 2, &body).unwrap();
            }
            tag
        });

        tauri::async_runtime::block_on(async {
            let poll = || NativeControl::Poll {
                presentation: TraySnapshot::default(),
            };
            let initial = {
                let client = client.clone();
                tauri::async_runtime::spawn(async move { client.control(poll()).await })
            };
            held.await.unwrap();
            let wake_stamp = crate::macos_power::local_repair_epoch()
                .expect("awake macOS test host")
                .wake_stamp();
            assert!(crate::macos_power::dispatch_wake_is_current(wake_stamp));
            let allowed = Arc::new(AtomicBool::new(true));
            let guard = {
                let allowed = Arc::clone(&allowed);
                WakeDispatchGuard::new(wake_stamp, move || allowed.load(Ordering::SeqCst))
            };
            let mut start =
                Box::pin(client.exchange_wake_mutation(Request::start(String::new()), guard));
            tokio::select! {
                biased;
                _ = &mut start => panic!("stall Start must be waiting behind the first poll"),
                _ = tokio::task::yield_now() => {}
            }
            allowed.store(false, Ordering::SeqCst);
            release.send(()).unwrap();
            initial.await.unwrap().unwrap();
            let error = start.await.unwrap_err();
            assert!(error
                .get_ref()
                .is_some_and(|source| source.is::<NativeDispatchDeferred>()));
            client.control(poll()).await.unwrap();
        });
        assert_eq!(worker.join().unwrap(), 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cancelling_a_forwarded_singleton_start_or_stop_prevents_native_dispatch() {
        use nelomai_unix_service::Request;
        for request in [Request::start(String::new()), Request::stop_if_unowned()] {
            assert_cancelled_before_helper(request);
        }
    }

    #[cfg(target_os = "macos")]
    fn assert_cancelled_before_helper(request: nelomai_unix_service::Request) {
        use nelomai_unix_service::{Response, ServiceError, ServiceTransport, UnixSocketTransport};

        let (stream, mut common) = NativeStream::pair().unwrap();
        let client = NativeClient::new(stream).unwrap();
        let (handoff, handed_off) = tokio::sync::oneshot::channel();
        let (cancelled, wait_for_cancellation) = std::sync::mpsc::channel();
        let directory = tempfile::tempdir().unwrap();
        let native_socket = directory.path().join("start.sock");
        let helper = std::os::unix::net::UnixListener::bind(&native_socket).unwrap();
        helper.set_nonblocking(true).unwrap();

        let worker = std::thread::spawn(move || {
            common
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let (tag, body) = read_native_frame(&mut common).unwrap();
            assert_eq!(tag, NATIVE_WAKE_MUTATION);
            let endpoint = crate::macos_storage::receive_endpoint(&mut common).unwrap();
            let (request, guard) = wake_mutation_request(&body, endpoint).unwrap();
            assert!(guard.is_current());
            handoff.send(()).unwrap();
            wait_for_cancellation
                .recv_timeout(Duration::from_secs(3))
                .unwrap();

            let transport = UnixSocketTransport::new(native_socket);
            let result =
                tauri::async_runtime::block_on(transport.exchange_wake_mutation(request, guard));
            assert!(matches!(result, Err(ServiceError::WakeDispatchDeferred)));
            let reply = serde_json::to_vec(&Response::failure(
                nelomai_client_tunnel::WAKE_DISPATCH_DEFERRED,
            ))
            .unwrap();
            write_native_frame(&mut common, tag, &reply).unwrap();
            assert_eq!(read_native_frame(&mut common).unwrap().0, 2);
            let reply = serde_json::to_vec(&NativeReply::Actions { actions: vec![] }).unwrap();
            write_native_frame(&mut common, 2, &reply).unwrap();
        });

        tauri::async_runtime::block_on(async {
            let stamp = crate::macos_power::local_repair_epoch()
                .expect("awake macOS test host")
                .wake_stamp();
            let guard = WakeDispatchGuard::new(stamp, || true);
            let mut exchange = Box::pin(client.exchange_wake_mutation(request, guard));
            tokio::select! {
                result = &mut exchange => panic!("mutation must wait for Common: {result:?}"),
                result = handed_off => result.unwrap(),
            }
            drop(exchange);
            cancelled.send(()).unwrap();
            client
                .control(NativeControl::Poll {
                    presentation: TraySnapshot::default(),
                })
                .await
                .unwrap();
        });
        worker.join().unwrap();
        assert!(matches!(helper.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn common_stall_start_requires_a_start_and_retains_the_cancel_peer() {
        use nelomai_unix_service::Request;

        let body = |stamp: i64, request: Request| {
            let mut body = stamp.to_le_bytes().to_vec();
            body.extend_from_slice(&u64::MAX.to_le_bytes());
            serde_json::to_writer(&mut body, &request).unwrap();
            body
        };
        for body in [
            vec![0; 7],
            body(-1, Request::start(String::new())),
            body(0, Request::stop()),
        ] {
            let (_lifetime, peer) = NativeStream::pair().unwrap();
            assert!(wake_mutation_request(&body, peer).is_err());
        }
        let (lifetime, peer) = NativeStream::pair().unwrap();
        let stamp = crate::macos_power::local_repair_epoch()
            .expect("awake macOS test host")
            .wake_stamp();
        let (_, guard) = wake_mutation_request(
            &body(stamp.unwrap_or(0), Request::start(String::new())),
            peer,
        )
        .unwrap();
        assert!(guard.is_current());
        drop(lifetime);
        assert!(!guard.is_current());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn common_rebind_requires_the_recorded_wake_when_scoped() {
        let stamp = crate::macos_power::local_repair_epoch()
            .unwrap()
            .wake_stamp();
        let deadline = uptime_nanos().unwrap() + 5_000_000_000;
        let check = |expected: Option<i64>| {
            let (_caller, peer) = NativeStream::pair().unwrap();
            let mut body = deadline.to_le_bytes().to_vec();
            if let Some(expected) = expected {
                body.extend_from_slice(&expected.to_le_bytes());
            }
            stall_rebind_guard(&body, peer).unwrap().is_current()
        };
        assert!(check(None)); // Manual Start has no automatic wake scope.
        assert!(check(Some(stamp.unwrap_or_default())));
        assert!(!check(Some(stamp.unwrap_or_default() + 1)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn queued_pair_revocation_preserves_an_accepted_reply() {
        use nelomai_client_tunnel::redundancy::{protocol::Command, SessionScope};
        use nelomai_unix_service::Request;
        use std::os::fd::AsRawFd;
        let (stream, mut common) = NativeStream::pair().unwrap();
        let client = NativeClient::new(stream).unwrap();
        let (accepted, dispatched) = tokio::sync::oneshot::channel();
        let server = std::thread::spawn(move || {
            let (tag, body) = read_native_frame(&mut common).unwrap();
            assert_eq!(tag, NATIVE_WAKE_MUTATION);
            let peer = crate::macos_storage::receive_endpoint(&mut common).unwrap();
            let witness = peer.try_clone().unwrap();
            let (request, guard) = wake_mutation_request(&body, peer).unwrap();
            assert!(matches!(
                request,
                Request::Redundant {
                    request: Command::PrepareRecoveryStop { .. },
                    ..
                }
            ));
            assert!(guard.is_current());
            let mut expired = body.clone();
            expired[8..16].copy_from_slice(&0u64.to_le_bytes());
            let (_, expired) =
                wake_mutation_request(&expired, witness.try_clone().unwrap()).unwrap();
            assert!(!expired.is_current());
            accepted.send(()).unwrap();
            let mut fd = libc::pollfd {
                fd: witness.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut fd, 1, 3000) }, 1);
            assert!(!guard.is_current());
            write_native_frame(&mut common, tag, b"accepted").unwrap();
        });
        let stamp = crate::macos_power::local_repair_epoch()
            .unwrap()
            .wake_stamp();
        let guard = WakeDispatchGuard::new(stamp, || true)
            .with_uptime_deadline(Some(
                Duration::from_nanos(uptime_nanos().unwrap()) + Duration::from_secs(10),
            ))
            .with_cancellation(async move {
                dispatched.await.unwrap();
            });
        let request = Request::Redundant {
            protocol_version: nelomai_unix_service::PROTOCOL_VERSION,
            request: Command::PrepareRecoveryStop {
                scope: SessionScope {
                    runtime: nelomai_contracts::RuntimeSlot::Latest,
                    runtime_generation: 1,
                    connection_generation: 1,
                    session_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                },
                expected_revision: 1,
                expected_network_epoch: 1,
            },
        };
        let reply =
            tauri::async_runtime::block_on(client.exchange_wake_mutation(request, guard)).unwrap();
        assert_eq!(reply, b"accepted");
        server.join().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn common_stall_rebind_requires_a_well_formed_unexpired_deadline() {
        let (_live, peer) = NativeStream::pair().unwrap();
        assert!(matches!(
            stall_rebind_guard(&[0; 7], peer),
            Err(error) if error.kind() == io::ErrorKind::InvalidData
        ));

        let (_live, peer) = NativeStream::pair().unwrap();
        let past = uptime_nanos().unwrap().to_le_bytes();
        let guard = stall_rebind_guard(&past, peer).unwrap();
        assert!(!guard.is_current());
    }
}

#[derive(Clone)]
pub(crate) struct RemoteTransport;
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[async_trait::async_trait]
impl nelomai_unix_service::ServiceTransport for RemoteTransport {
    async fn exchange(
        &self,
        request: nelomai_unix_service::Request,
    ) -> Result<nelomai_unix_service::Response, nelomai_unix_service::ServiceError> {
        use nelomai_unix_service::*;
        let bytes = serde_json::to_vec(&request).map_err(|_| ServiceError::TruncatedFrame)?;
        let reply = native()
            .map_err(|_| ServiceError::TruncatedFrame)?
            .exchange(1, bytes)
            .await
            .map_err(|_| ServiceError::TruncatedFrame)?;
        serde_json::from_slice(&reply).map_err(|_| ServiceError::TruncatedFrame)
    }

    #[cfg(target_os = "macos")]
    async fn exchange_stall_rebind(
        &self,
        guard: StallRebindGuard,
    ) -> Result<nelomai_unix_service::Response, nelomai_unix_service::ServiceError> {
        use nelomai_unix_service::ServiceError;

        let reply = native()
            .map_err(|_| ServiceError::TruncatedFrame)?
            .exchange_stall_rebind(guard)
            .await
            .map_err(|error| match error.kind() {
                io::ErrorKind::Interrupted => ServiceError::DispatcherTimeout,
                _ => ServiceError::TruncatedFrame,
            })?;
        serde_json::from_slice(&reply).map_err(|_| ServiceError::TruncatedFrame)
    }

    #[cfg(target_os = "macos")]
    async fn exchange_wake_mutation(
        &self,
        request: nelomai_unix_service::Request,
        guard: WakeDispatchGuard,
    ) -> Result<nelomai_unix_service::Response, nelomai_unix_service::ServiceError> {
        use nelomai_unix_service::ServiceError;

        let reply = native()
            .map_err(|_| ServiceError::TruncatedFrame)?
            .exchange_wake_mutation(request, guard)
            .await
            .map_err(|error| {
                if error
                    .get_ref()
                    .is_some_and(|source| source.is::<NativeDispatchDeferred>())
                {
                    ServiceError::WakeDispatchDeferred
                } else {
                    ServiceError::TruncatedFrame
                }
            })?;
        serde_json::from_slice(&reply).map_err(|_| ServiceError::TruncatedFrame)
    }
}
#[cfg(windows)]
#[async_trait::async_trait]
impl nelomai_windows_service::ServiceTransport for RemoteTransport {
    async fn exchange(
        &self,
        request: nelomai_windows_service::Request,
    ) -> Result<nelomai_windows_service::Response, nelomai_windows_service::ServiceError> {
        use nelomai_windows_service::*;
        let bytes = serde_json::to_vec(&request).map_err(|_| ServiceError::TruncatedFrame)?;
        let reply = native()
            .map_err(|_| ServiceError::TruncatedFrame)?
            .exchange(1, bytes)
            .await
            .map_err(|_| ServiceError::TruncatedFrame)?;
        serde_json::from_slice(&reply).map_err(|_| ServiceError::TruncatedFrame)
    }
}

pub fn run() {
    let result = (|| -> Result<_, Box<dyn std::error::Error>> {
        let (mut auth, native_stream) =
            nelomai_client_container::desktop::capture_inherited_channels()?;
        #[cfg(unix)]
        let bytes = {
            use std::io::Read;
            auth.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut size = [0; 4];
            auth.read_exact(&mut size)?;
            let size = u32::from_le_bytes(size) as usize;
            if size > 65536 {
                return Err(io::Error::other("invalid runtime bootstrap").into());
            }
            let mut bytes = vec![0; size];
            auth.read_exact(&mut bytes)?;
            auth.set_read_timeout(None)?;
            bytes
        };
        #[cfg(windows)]
        let bytes = tauri::async_runtime::block_on(async {
            use tokio::io::AsyncReadExt;
            tokio::time::timeout(Duration::from_secs(10), async {
                let size = auth.read_u32_le().await? as usize;
                if size > 65536 {
                    return Err(io::Error::other("invalid runtime bootstrap"));
                }
                let mut bytes = vec![0; size];
                auth.read_exact(&mut bytes).await?;
                Ok(bytes)
            })
            .await
            .map_err(|_| io::Error::other("runtime bootstrap timeout"))?
        })?;
        let bootstrap: RuntimeBootstrapV1 = serde_json::from_slice(&bytes)?;
        bootstrap.runtime_paths()?;
        let native = Arc::new(NativeClient::new(native_stream)?);
        #[cfg(target_os = "macos")]
        {
            use nelomai_client_container::desktop::{read_native_frame, write_native_frame};
            let mut guard = native
                .stream
                .lock()
                .map_err(|_| io::Error::other("native unavailable"))?;
            let stream = guard
                .as_mut()
                .ok_or_else(|| io::Error::other("native unavailable"))?;
            write_native_frame(stream, 2, &serde_json::to_vec(&NativeControl::OpenStorage)?)?;
            let (tag, reply) = read_native_frame(stream)?;
            if tag != 2
                || !matches!(
                    serde_json::from_slice::<NativeReply>(&reply)?,
                    NativeReply::Done
                )
            {
                return Err(io::Error::other("common storage unavailable").into());
            }
            let storage = crate::macos_storage::receive_endpoint(stream)?;
            STORAGE
                .set(Arc::new(crate::macos_storage::StorageClient::new(storage)?))
                .map_err(|_| io::Error::other("duplicate runtime storage"))?;
        }
        NATIVE
            .set(native)
            .map_err(|_| io::Error::other("duplicate runtime bootstrap"))?;
        Ok((auth, bootstrap))
    })();
    let (auth, bootstrap) = result.unwrap_or_else(|_| std::process::exit(1));
    crate::run_product(move |app| setup_desktop(app, auth, bootstrap));
}

fn setup_desktop(
    app: &mut tauri::App,
    auth: AuthStream,
    bootstrap: RuntimeBootstrapV1,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "macos"))]
    use nelomai_client_storage::ProtectedRecordFactory;
    let paths = bootstrap.runtime_paths()?;
    app.manage(crate::support_diagnostics::SupportDataRoot(
        bootstrap.data_root.clone(),
    ));
    let selected = paths
        .iter()
        .find(|path| {
            path.slot() == bootstrap.target.runtime_slot
                && path.runtime_version() == bootstrap.target.runtime_version
        })
        .ok_or_else(|| io::Error::other("runtime record unavailable"))?
        .clone();
    #[cfg(target_os = "linux")]
    let fallback = Some(bootstrap.data_root.join("credentials"));
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let fallback = None;
    #[cfg(not(target_os = "macos"))]
    let records = nelomai_client_storage::SystemRecordFactory::new("primary", fallback);
    #[cfg(target_os = "macos")]
    let indexes: std::collections::HashMap<_, _> = paths
        .iter()
        .enumerate()
        .map(|(index, path)| (path.namespace().to_owned(), index as u8))
        .collect();
    let open = |path: nelomai_client_storage::RuntimePaths| {
        #[cfg(target_os = "macos")]
        let backend = crate::macos_storage::RemoteRecord::new(
            STORAGE
                .get()
                .expect("private storage established before product startup")
                .clone(),
            indexes[path.namespace()],
        );
        #[cfg(not(target_os = "macos"))]
        let backend = records.record(path.namespace());
        RuntimeRecordOwner::new(ProtectedRuntimeStore::new(backend, path))
    };
    let retained = paths
        .into_iter()
        .filter(|path| path != &selected)
        .map(open)
        .collect();
    let record = open(selected.clone());
    let tunnel = Arc::new(platform::tunnel_controller(app.handle().clone()));
    let local = CoreLocalStop::new(tunnel.clone());
    let admission = Arc::new(ChildAdmission::new(
        bootstrap.incarnation,
        local.runtime_writer_gates(),
        Arc::new(RuntimeRecordInventory::new(record.clone(), retained)),
    ));
    #[cfg(unix)]
    auth.set_nonblocking(true)?;
    #[cfg(unix)]
    let port = tauri::async_runtime::block_on(async {
        tokio::net::UnixStream::from_std(auth).map(|stream| {
            Arc::new(PrivateRuntimeAuthClient::new(
                stream,
                admission,
                local.clone(),
            ))
        })
    })?;
    #[cfg(windows)]
    let port = tauri::async_runtime::block_on(async {
        Arc::new(PrivateRuntimeAuthClient::new(
            auth,
            admission,
            local.clone(),
        ))
    });
    let api = ClientApi::new(PANEL_BASE)?.with_app_version(&bootstrap.target.container_version)?;
    let diagnostics = Arc::new(
        diagnostics::AppDiagnostics::new(
            selected
                .operational_state
                .parent()
                .ok_or_else(|| io::Error::other("runtime diagnostics unavailable"))?
                .join("diagnostics"),
            resource_usage::ResourceSnapshot::capture(app.handle()),
        )?
        .with_update_log_directory(bootstrap.data_root.join("common")),
    );
    let transport_diagnostics = diagnostics.clone();
    let api = api.with_control_diagnostics(move |code, ms| {
        transport_diagnostics.record_timed_named(
            "control.transport.failed",
            None,
            None,
            Some(code),
            std::time::Duration::from_millis(ms),
        )
    });
    let preferences = Arc::new(preferences::AppPreferenceStore::open_runtime(
        &selected.preferences,
        &bootstrap.data_root.join("preferences.json"),
    )?);
    let application = Arc::new(ClientApplication::with_split_tunnel_store_and_preflight(
        Arc::new(api),
        Arc::new(record.operational()),
        Arc::new(record.split()),
        port.clone(),
        local,
        diagnostics.clone(),
        port.clone(),
    ));
    application.set_dns_servers(preferences.get().dns_provider.servers());
    let split = Arc::new(SplitTunnelScheduler::new());
    let push = Arc::new(PushRegistrationScheduler::new());
    let metrics = Arc::new(connection_metrics::ConnectionMetricsTracker::new());
    let intent = Arc::new(connection_intent::DesktopConnectionIntent::new(
        app.handle().clone(),
        application.clone(),
        diagnostics.clone(),
    ));
    app.manage(port.clone());
    app.manage(Arc::new(runtime_control::RuntimeControls::new(
        port.clone(),
        &bootstrap.target,
    )));
    // Read only after the private native bootstrap has authenticated this owner.
    let update_protocol = if std::env::var("NELOMAI_UPDATE_PROTOCOL").as_deref() == Ok("2") {
        2
    } else {
        1
    };
    app.manage(Arc::new(
        updates::NativeUpdater::new(port.clone()).with_update_protocol(update_protocol),
    ));
    app.manage(application.clone());
    app.manage(tunnel.clone());
    app.manage(diagnostics.clone());
    app.manage(preferences);
    app.manage(split.clone());
    app.manage(push.clone());
    app.manage(metrics.clone());
    app.manage(intent.clone());
    let handle = app.handle().clone();
    let startup_diagnostics = diagnostics.clone();
    let startup = Arc::new(runtime_startup::RuntimeStartup::new(move || {
        diagnostics.record_named("startup.runtime_ready", None, None, None);
        start_split_tunnel_scheduler(application.clone(), split);
        start_physical_network_scheduler(application.clone(), intent.clone());
        start_pending_stop_scheduler(application.clone(), intent.clone());
        intent.spawn();
        start_connection_metrics_scheduler(
            handle.clone(),
            application.clone(),
            tunnel.clone(),
            metrics,
            diagnostics.clone(),
        );
        start_automatic_diagnostics_scheduler(
            handle.clone(),
            application.clone(),
            tunnel,
            diagnostics,
        );
        start_push_registration_scheduler(handle.clone(), application, push);
    }));
    app.manage(startup.clone());
    tauri::async_runtime::spawn(async move {
        let _ = startup
            .recover(|| async { runtime_startup::request_ready(&port, &startup_diagnostics).await })
            .await;
    });
    // Tray/lifecycle remain available even when record admission needs recovery.
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let presentation = desktop::runtime_presentation(&handle).await;
            let Ok(owner) = native() else {
                break;
            };
            let reply = owner.control(NativeControl::Poll { presentation }).await;
            match reply {
                Ok(NativeReply::Actions { actions }) => {
                    for action in actions {
                        match action {
                            RuntimeAction::Show => desktop::show_window(&handle),
                            RuntimeAction::Toggle => desktop::toggle_connection(handle.clone()),
                            RuntimeAction::Quit => desktop::quit_application(handle.clone()),
                        }
                    }
                }
                _ => {
                    desktop::quit_application(handle.clone());
                    if owner.stream.lock().map_or(true, |stream| stream.is_none()) {
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    Ok(())
}
