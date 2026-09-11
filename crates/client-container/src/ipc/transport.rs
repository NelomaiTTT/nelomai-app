use super::*;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use tokio::sync::{mpsc, oneshot, watch};

type Queued = (FrameV1, Instant);
pub(super) struct Outbox {
    sender: mpsc::Sender<Queued>,
    closed: watch::Sender<bool>,
    next_id: AtomicU64,
}
impl Outbox {
    pub fn close(&self) {
        self.closed.send_replace(true);
    }
    pub fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }
    pub fn cancellation(&self) -> watch::Receiver<bool> {
        self.closed.subscribe()
    }
    pub fn id(&self) -> Result<u64, PrivateError> {
        self.next_id
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |old| old.checked_add(1))
            .map_err(|_| {
                self.close();
                PrivateError::Closed
            })
    }
    pub fn enqueue(&self, frame: FrameV1, deadline: Instant) -> Result<(), PrivateError> {
        validate_frame_size(&frame).inspect_err(|_| self.close())?;
        if self.is_closed() {
            return Err(PrivateError::Closed);
        }
        if Instant::now() >= deadline {
            self.close();
            return Err(PrivateError::Timeout);
        }
        self.sender.try_send((frame, deadline)).map_err(|_| {
            self.close();
            PrivateError::Closed
        })
    }
}
pub(super) async fn closed(receiver: &mut watch::Receiver<bool>) {
    loop {
        if *receiver.borrow_and_update() {
            return;
        }
        if receiver.changed().await.is_err() {
            return;
        }
    }
}
/// Drop cancellation closes the channel. This drops partial async socket I/O
/// through the pumps and cannot leave a request eligible for a later grant.
pub(super) struct RequestLifetime {
    pub outbox: Arc<Outbox>,
    pub complete: bool,
}
impl Drop for RequestLifetime {
    fn drop(&mut self) {
        if !self.complete {
            self.outbox.close();
        }
    }
}

pub(super) fn connect<S>(stream: S) -> (Arc<Outbox>, mpsc::Receiver<(FrameV1, Instant)>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, mut receiver) = mpsc::channel::<Queued>(OUTBOX_CAPACITY);
    let (incoming, frames) = mpsc::channel(OUTBOX_CAPACITY);
    let (cancel, _) = watch::channel(false);
    let outbox = Arc::new(Outbox {
        sender,
        closed: cancel,
        next_id: AtomicU64::new(1),
    });
    let (mut read, mut write) = tokio::io::split(stream);
    let reader_box = outbox.clone();
    let mut reader_cancel = outbox.cancellation();
    tokio::spawn(async move {
        loop {
            // Idle channels stay alive. A partial frame gets one 10s budget
            // starting at its first byte, including the rest of its header.
            let first = tokio::select! { biased;
                _ = closed(&mut reader_cancel) => break,
                value = read.read_u8() => match value { Ok(value) => value, Err(_) => break },
            };
            let started = Instant::now();
            let prefix = [first];
            let mut prefixed = prefix.as_slice().chain(&mut read);
            let frame = tokio::select! { biased;
                _ = closed(&mut reader_cancel) => break,
                result = read_frame(&mut prefixed, started + REQUEST_BUDGET) => match result { Ok(frame) => frame, Err(_) => break },
            };
            let deadline = started + Duration::from_millis(frame.remaining_ms);
            if Instant::now() >= deadline || incoming.try_send((frame, deadline)).is_err() {
                break;
            }
        }
        reader_box.close();
    });
    let writer_box = outbox.clone();
    let mut writer_cancel = outbox.cancellation();
    tokio::spawn(async move {
        loop {
            let item = tokio::select! { biased;
                _ = closed(&mut writer_cancel) => break,
                item = receiver.recv() => match item { Some(item) => item, None => break },
            };
            let result = tokio::select! { biased;
                _ = closed(&mut writer_cancel) => break,
                result = write_frame(&mut write, item.0, item.1) => result,
            };
            if result.is_err() {
                break;
            }
        }
        writer_box.close();
    });
    (outbox, frames)
}

pub(super) struct Pending<T> {
    entries: Mutex<HashMap<u64, oneshot::Sender<T>>>,
}
impl<T> Default for Pending<T> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}
impl<T> Pending<T> {
    pub fn insert(&self, id: u64) -> Result<oneshot::Receiver<T>, PrivateError> {
        let mut entries = self.entries.lock().map_err(|_| PrivateError::Closed)?;
        if entries.len() >= MAX_PENDING || entries.contains_key(&id) {
            return Err(PrivateError::Closed);
        }
        let (sender, receiver) = oneshot::channel();
        entries.insert(id, sender);
        Ok(receiver)
    }
    pub fn finish(&self, id: u64, value: T) -> Result<(), PrivateError> {
        self.entries
            .lock()
            .map_err(|_| PrivateError::Closed)?
            .remove(&id)
            .ok_or(PrivateError::Protocol)?
            .send(value)
            .map_err(|_| PrivateError::Cancelled)
    }
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }
}

pub(super) fn scope(access: &AccessSnapshot) -> RuntimeAuthScope {
    RuntimeAuthScope {
        auth_epoch: access.auth_epoch(),
        family: access.family().into(),
        identity: access.identity().clone(),
    }
}
pub(super) fn broker_error(error: crate::BrokerError) -> PrivateError {
    use crate::BrokerError;
    match error {
        BrokerError::Cancelled | BrokerError::IdentityMismatch => PrivateError::Cancelled,
        BrokerError::Timeout => PrivateError::Timeout,
        BrokerError::RefreshPending => PrivateError::RefreshPending,
        BrokerError::RefreshRejected => PrivateError::RefreshRejected,
        BrokerError::AuthenticationOutcomeUnknown => PrivateError::OutcomeUnknown,
        BrokerError::AccessUnavailable => PrivateError::AccessUnavailable,
        BrokerError::Api(_) => PrivateError::Service,
        BrokerError::Storage(_) | BrokerError::RecoveryRequired => PrivateError::RecoveryRequired,
    }
}
pub(super) fn core_error(error: PrivateError) -> nelomai_client_core::CoreError {
    use nelomai_client_core::{CoreApiError, CoreError};
    match error {
        PrivateError::Cancelled | PrivateError::Closed => CoreError::StartCancelled,
        PrivateError::OutcomeUnknown => CoreError::AuthenticationOutcomeUnknown,
        PrivateError::AccessUnavailable => CoreError::AccessExpired,
        PrivateError::Timeout | PrivateError::Service | PrivateError::RefreshPending => {
            CoreError::Api(CoreApiError::Retryable)
        }
        PrivateError::Protocol | PrivateError::RecoveryRequired | PrivateError::RefreshRejected => {
            CoreError::AuthRecoveryRequired
        }
    }
}
