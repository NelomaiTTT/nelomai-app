//! Native Activity events use the admitted private channel. No WebView visibility
//! authority and no Android periodic updater. Events are ordered across JNI calls.
use nelomai_client_container::{
    host::{HostRequestV1, HostResponseV1, UpdateCheckReason, UpdateRequestV2},
    ipc::{PrivateError, PrivateRuntimeAuthClient},
};
use std::{
    future::Future,
    sync::{Arc, Mutex, OnceLock},
};
use tokio::sync::mpsc;

pub(crate) struct UiUpdate {
    pub foreground: bool,
    pub new_user_launch: bool,
    pub launch_session_id: Option<String>,
    // 0 = permission only, 1 = initial UI, 2 = actual return from background.
    pub reason: u8,
}

type UiChannel = (
    mpsc::UnboundedSender<UiUpdate>,
    Mutex<Option<mpsc::UnboundedReceiver<UiUpdate>>>,
);
fn channel() -> &'static UiChannel {
    static CHANNEL: OnceLock<UiChannel> = OnceLock::new();
    CHANNEL.get_or_init(|| {
        let (sender, receiver) = mpsc::unbounded_channel();
        (sender, Mutex::new(Some(receiver)))
    })
}
pub(crate) fn submit(update: UiUpdate) {
    // Native lifecycle only, no periodic producer. Admission can start after the
    // first onResume, so preserve the one-shot launch token until the owner is ready.
    let _ = channel().0.send(update);
}
pub(crate) fn start(protocol: u32, owner: Arc<PrivateRuntimeAuthClient>) {
    let Some(receiver) = channel()
        .1
        .lock()
        .ok()
        .and_then(|mut receiver| receiver.take())
    else {
        return;
    };
    if protocol != 2 {
        return;
    }
    tokio::spawn(relay(protocol, receiver, move |request| {
        let owner = owner.clone();
        async move {
            match owner
                .owner_request(HostRequestV1::UpdateV2 { request })
                .await?
            {
                HostResponseV1::UpdateV2 { .. } => Ok(()),
                _ => Err(PrivateError::Protocol),
            }
        }
    }));
}

pub(crate) async fn relay<F, Fut>(
    protocol: u32,
    mut receiver: mpsc::UnboundedReceiver<UiUpdate>,
    mut send: F,
) where
    F: FnMut(UpdateRequestV2) -> Fut,
    Fut: Future<Output = Result<(), PrivateError>>,
{
    while let Some(update) = receiver.recv().await {
        if matches!(
            forward(protocol, update, &mut send).await,
            Err(PrivateError::Closed | PrivateError::Protocol | PrivateError::Cancelled)
        ) {
            break;
        }
        // A failed check/UX-state write must not discard the next native pause.
        // Retry only on a new lifecycle event; no timer or request replay.
    }
}

pub(crate) async fn forward<F, Fut>(
    protocol: u32,
    update: UiUpdate,
    mut send: F,
) -> Result<(), PrivateError>
where
    F: FnMut(UpdateRequestV2) -> Fut,
    Fut: Future<Output = Result<(), PrivateError>>,
{
    // Capability must come from Binder admission, never from probing a strict V1 owner.
    if protocol != 2 {
        return Ok(());
    }
    send(UpdateRequestV2::UiLifecycle {
        foreground: update.foreground,
        new_user_launch: update.new_user_launch,
        launch_session_id: update.launch_session_id,
    })
    .await?;
    if update.foreground {
        let reason = match update.reason {
            1 => Some(UpdateCheckReason::Startup),
            2 => Some(UpdateCheckReason::Foreground),
            _ => None,
        };
        if let Some(reason) = reason {
            send(UpdateRequestV2::Check { reason }).await?;
        }
    }
    Ok(())
}
