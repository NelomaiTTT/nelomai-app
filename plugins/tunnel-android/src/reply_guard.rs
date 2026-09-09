use std::{
    future::{poll_fn, Future},
    pin::Pin,
};

// Tauri 2.11.5 unwraps delivery to its oneshot receiver. Dropping that receiver
// after dispatch makes a late JNI reply abort the process. Poll inline so an
// unpolled/cancelled start intent cannot be dispatched by a background task.
pub(crate) async fn await_plugin_reply<F: Future + Send + 'static>(future: F) -> F::Output {
    let mut pending = PendingReply(Some(Box::pin(future)));
    poll_fn(|cx| {
        let result = pending.0.as_mut().unwrap().as_mut().poll(cx);
        if result.is_ready() {
            pending.0 = None;
        }
        result
    })
    .await
}

struct PendingReply<F: Future + Send + 'static>(Option<Pin<Box<F>>>);

impl<F: Future + Send + 'static> Drop for PendingReply<F> {
    fn drop(&mut self) {
        if let Some(future) = self.0.take() {
            // Only the already-dispatched reply survives caller cancellation.
            // Service calls resolve/reject via Kotlin's request watchdog; do not
            // add a Rust timeout here, which would recreate the dropped receiver.
            tauri::async_runtime::spawn(async move {
                let _ = future.await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::await_plugin_reply;
    use std::{
        future::{poll_fn, Future},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        task::Poll,
        time::Duration,
    };
    use tokio::sync::oneshot;

    // The platform callback outlives the caller and uses send(...).unwrap(),
    // just like Tauri 2.11.5's run_mobile_plugin_async callback. JNI itself
    // cannot run on the host, so keep the real Tokio receiver at this boundary.
    async fn pending_reply<T: Send + 'static>(
        rx: oneshot::Receiver<T>,
        consumed: oneshot::Sender<()>,
    ) -> T {
        let reply = rx.await.unwrap();
        let _ = consumed.send(());
        reply
    }

    #[test]
    fn cancellation_keeps_late_success_and_rejection_receivers_alive() {
        tauri::async_runtime::block_on(async {
            for reply in [Ok(1865_u64), Err("tunnel_service_timeout")] {
                let (tx, rx) = oneshot::channel();
                let (consumed_tx, consumed_rx) = oneshot::channel();
                let dispatched = Arc::new(AtomicBool::new(false));
                let observed = dispatched.clone();
                let mut call = Box::pin(await_plugin_reply(async move {
                    observed.store(true, Ordering::SeqCst);
                    pending_reply(rx, consumed_tx).await
                }));
                poll_fn(|cx| {
                    assert!(call.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                assert!(
                    dispatched.load(Ordering::SeqCst),
                    "dispatch must occur inline"
                );

                // Cancellation must return without waiting for Android's reply.
                drop(call);
                tx.send(reply).expect("late JNI reply receiver was dropped");
                tokio::time::timeout(Duration::from_secs(1), consumed_rx)
                    .await
                    .expect("cancelled call did not drain its late reply")
                    .unwrap();
            }
        });
    }

    #[test]
    fn deadline_returns_before_the_late_reply() {
        tauri::async_runtime::block_on(async {
            let (tx, rx) = oneshot::channel();
            let (consumed_tx, consumed_rx) = oneshot::channel();
            let result = tokio::time::timeout(
                Duration::from_millis(10),
                await_plugin_reply(pending_reply(rx, consumed_tx)),
            )
            .await;

            assert!(
                result.is_err(),
                "a missing reply must respect the caller deadline"
            );
            tx.send(1865)
                .expect("timed out JNI reply receiver was dropped");
            tokio::time::timeout(Duration::from_secs(1), consumed_rx)
                .await
                .expect("timed out call did not drain its late reply")
                .unwrap();
        });
    }

    #[test]
    fn unpolled_call_does_not_dispatch_after_cancellation() {
        let dispatched = Arc::new(AtomicBool::new(false));
        let observed = dispatched.clone();
        let call = await_plugin_reply(async move {
            observed.store(true, Ordering::SeqCst);
        });

        drop(call);
        assert!(!dispatched.load(Ordering::SeqCst));
    }

    #[test]
    fn completed_calls_preserve_success_and_error_results() {
        tauri::async_runtime::block_on(async {
            for reply in [Ok(1865_u64), Err("tunnel_service_timeout")] {
                let (tx, rx) = oneshot::channel();
                tx.send(reply).unwrap();
                assert_eq!(
                    await_plugin_reply(async move { rx.await.unwrap() }).await,
                    reply
                );
            }
        });
    }
}
