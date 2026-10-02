//! Single-reader Windows engine input routing, portable for fake-channel tests.
//! Legacy brokered SCM effects remain in ProcessDispatcher; the scoped pair
//! adapter has its own guarded SCM calls. Only the owner thread can request a
//! broker primitive; no primitive caller reads stdin. Idle primitives need the
//! manager's negotiated idle-tick exchange to keep the dispatcher broker active.
use nelomai_client_tunnel::redundancy::engine_channel::ChannelEvent;
use nelomai_contracts::dispatcher::{self as d, EnginePrimitive};
use serde::Deserialize;
use std::{
    cell::RefCell,
    io::{self, BufRead, BufReader, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    time::Duration,
};

const PRIMITIVE_TIMEOUT: Duration = Duration::from_secs(40);

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Waiting,
    Replied,
    Closed,
    Failed,
}

pub struct InputRouter {
    frames: SyncSender<ChannelEvent>,
    replies: SyncSender<io::Result<bool>>,
    state: Arc<Mutex<State>>,
    cancelled: Arc<AtomicBool>,
}
pub struct PrimitiveClient {
    replies: Receiver<io::Result<bool>>,
    state: Arc<Mutex<State>>,
    cancelled: Arc<AtomicBool>,
}
impl PrimitiveClient {
    /// SAME process-owned reader/owner cancellation origin. This is a forward
    /// stop signal only, never a native cleanup or authorization capability.
    pub fn cancellation(&self) -> Arc<AtomicBool> {
        self.cancelled.clone()
    }
}
impl Drop for PrimitiveClient {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}
impl Drop for InputRouter {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

fn failed() -> io::Error {
    io::Error::other("engine_primitive_channel_failed")
}

/// Both queues have capacity one. A dispatcher serializes exchanges, so at
/// most one control frame may precede an outstanding primitive reply.
pub fn channel() -> (InputRouter, Receiver<ChannelEvent>, PrimitiveClient) {
    let (frame_tx, frames) = mpsc::sync_channel(1);
    let (reply_tx, replies) = mpsc::sync_channel(1);
    let state = Arc::new(Mutex::new(State::Idle));
    let cancelled = Arc::new(AtomicBool::new(false));
    (
        InputRouter {
            frames: frame_tx,
            replies: reply_tx,
            state: state.clone(),
            cancelled: cancelled.clone(),
        },
        frames,
        PrimitiveClient {
            replies,
            state,
            cancelled,
        },
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrimitiveAck {
    primitive_ok: bool,
}

impl InputRouter {
    fn poison(&self) -> io::Error {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Ok(mut state) = self.state.lock() {
            *state = State::Failed;
        }
        let _ = self.replies.try_send(Err(failed()));
        failed()
    }

    pub fn route_frame(&mut self, frame: Vec<u8>) -> io::Result<()> {
        let body = d::frame_body(&frame, d::MAX_ENGINE_FRAME).map_err(|_| self.poison())?;
        let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| self.poison())?;
        if value.get("primitive_ok").is_some() {
            // Deserialize again into a strict shape: Value alone would silently
            // accept duplicate keys or additional command fields.
            let ack: PrimitiveAck = serde_json::from_slice(
                d::frame_body(&frame, d::MAX_DISPATCHER_FRAME).map_err(|_| self.poison())?,
            )
            .map_err(|_| self.poison())?;
            let mut state = self.state.lock().map_err(|_| failed())?;
            if *state != State::Waiting {
                drop(state);
                return Err(self.poison());
            }
            *state = State::Replied;
            if self.replies.try_send(Ok(ack.primitive_ok)).is_err() {
                drop(state);
                return Err(self.poison());
            }
            return Ok(());
        }
        if *self.state.lock().map_err(|_| failed())? == State::Failed {
            return Err(failed());
        }
        // Never block the sole reader behind a full frame queue while its
        // owner is waiting for the primitive ack that follows on this pipe.
        self.frames
            .try_send(ChannelEvent::Frame(frame))
            .map_err(|_| self.poison())
    }

    /// Wake a primitive waiter before sending the terminal frame event. This
    /// ordering also allows a full frame queue to drain on fatal input failure.
    pub fn finish(&mut self, error: Option<io::Error>) {
        // Publish BEFORE mutex acquisition / the bounded terminal queue send:
        // a busy native owner must see cancellation without draining frames.
        self.cancelled.store(true, Ordering::SeqCst);
        if let Ok(mut state) = self.state.lock() {
            if error.is_some() || *state == State::Failed {
                *state = State::Failed;
            } else {
                *state = State::Closed;
            }
        }
        let _ = self.replies.try_send(Err(failed()));
        let _ = self.frames.send(match error {
            Some(error) => ChannelEvent::ReadError(error),
            None => ChannelEvent::Eof,
        });
    }
}

/// Starts exactly one detached reader for this process's owned input. As with
/// the shared timed channel, the caller must exit the engine after the runner
/// returns; it must not join a reader blocked forever in the process pipe.
pub fn spawn_input<R: Read + Send + 'static>(
    reader: R,
) -> io::Result<(Receiver<ChannelEvent>, PrimitiveClient)> {
    let (mut router, frames, client) = channel();
    std::thread::Builder::new()
        .name("windows-engine-input".into())
        .spawn(move || {
            let mut reader = BufReader::new(reader);
            loop {
                let frame = match reader.fill_buf() {
                    Ok([]) => {
                        router.finish(None);
                        break;
                    }
                    Ok(_) => d::read_frame(&mut reader, d::MAX_ENGINE_FRAME),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => Err(error),
                };
                match frame.and_then(|frame| router.route_frame(frame)) {
                    Ok(()) => (),
                    Err(error) => {
                        router.finish(Some(error));
                        break;
                    }
                }
            }
        })?;
    Ok((frames, client))
}

thread_local! { static OWNER: RefCell<Option<PrimitiveClient>> = const { RefCell::new(None) }; }

/// Installs the reply receiver only on the serialized engine owner thread.
pub fn with_owner<T>(client: PrimitiveClient, run: impl FnOnce() -> T) -> io::Result<T> {
    OWNER.with(|owner| {
        let mut owner = owner.try_borrow_mut().map_err(|_| failed())?;
        if owner.is_some() {
            return Err(failed());
        }
        *owner = Some(client);
        Ok(())
    })?;
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            OWNER.with(|owner| {
                owner.borrow_mut().take();
            });
        }
    }
    let _clear = Clear;
    Ok(run())
}

pub fn ensure_healthy() -> io::Result<()> {
    OWNER.with(|owner| {
        let owner = owner.try_borrow().map_err(|_| failed())?;
        let client = owner.as_ref().ok_or_else(failed)?;
        if *client.state.lock().map_err(|_| failed())? == State::Failed {
            Err(failed())
        } else {
            Ok(())
        }
    })
}

pub fn request_primitive(action: EnginePrimitive, writer: &mut impl Write) -> io::Result<()> {
    OWNER.with(|owner| {
        let owner = owner.try_borrow_mut().map_err(|_| failed())?;
        let client = owner.as_ref().ok_or_else(failed)?;
        {
            let mut state = client.state.lock().map_err(|_| failed())?;
            if *state != State::Idle {
                return Err(failed());
            }
            *state = State::Waiting;
        }
        let result = (|| {
            writer.write_all(&d::encode_frame(&d::PrimitiveRequest {
                engine_primitive: action,
            })?)?;
            writer.flush()?;
            let ack = client
                .replies
                .recv_timeout(PRIMITIVE_TIMEOUT)
                .map_err(|_| failed())??;
            let mut state = client.state.lock().map_err(|_| failed())?;
            if *state != State::Replied {
                return Err(failed());
            }
            *state = State::Idle;
            Ok(ack)
        })();
        match result {
            Ok(true) => Ok(()),
            Ok(false) => Err(io::Error::other("dispatcher_primitive_failed")),
            Err(error) => {
                client.cancelled.store(true, Ordering::SeqCst);
                if let Ok(mut state) = client.state.lock() {
                    *state = State::Failed;
                }
                Err(error)
            }
        }
    })
}
