//! Own blocking work until completion; cancellation aborts jobs still queued.
use std::io;

pub(crate) async fn read<T: Send + 'static>(
    read: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    struct AbortOnDrop<T>(tokio::task::JoinHandle<io::Result<T>>);
    impl<T> Drop for AbortOnDrop<T> {
        fn drop(&mut self) {
            // Tokio cannot abort an OS call already running. Its closure owns
            // any admission permit until return. Queued jobs never enter it.
            self.0.abort();
        }
    }
    let mut task = AbortOnDrop(tokio::task::spawn_blocking(read));
    (&mut task.0)
        .await
        .map_err(|_| io::Error::other("blocking_read_failed"))?
}
