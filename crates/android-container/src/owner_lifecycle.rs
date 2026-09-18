use std::{
    ops::Deref,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

pub(crate) struct OwnerEntry<T> {
    state: Mutex<OwnerState<T>>,
    idle: Condvar,
}

struct OwnerState<T> {
    owner: Option<Arc<T>>,
    leases: usize,
    closing: bool,
}

pub(crate) struct OwnerLease<T> {
    entry: Arc<OwnerEntry<T>>,
    owner: Option<Arc<T>>,
}

impl<T> OwnerEntry<T> {
    pub(crate) fn new(owner: T) -> Self {
        Self {
            state: Mutex::new(OwnerState {
                owner: Some(Arc::new(owner)),
                leases: 0,
                closing: false,
            }),
            idle: Condvar::new(),
        }
    }

    pub(crate) fn acquire(self: &Arc<Self>) -> Result<OwnerLease<T>, ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.closing {
            return Err(());
        }
        let owner = state.owner.as_ref().ok_or(())?.clone();
        state.leases = state.leases.checked_add(1).ok_or(())?;
        Ok(OwnerLease {
            entry: self.clone(),
            owner: Some(owner),
        })
    }
}

impl<T: Send + Sync + 'static> OwnerEntry<T> {
    pub(crate) fn close(self: &Arc<Self>, timeout: Duration) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return false,
        };
        if state.closing {
            return false;
        }
        state.closing = true;
        drop(state);

        let (closed, acknowledgement) = std::sync::mpsc::sync_channel(1);
        let entry = self.clone();
        std::thread::spawn(move || {
            let owner = {
                let Ok(mut state) = entry.state.lock() else {
                    return;
                };
                while state.leases != 0 {
                    let Ok(next) = entry.idle.wait(state) else {
                        return;
                    };
                    state = next;
                }
                state.owner.take()
            };
            drop(owner);
            let _ = closed.send(());
        });
        acknowledgement.recv_timeout(timeout).is_ok()
    }
}

impl<T> Deref for OwnerLease<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.owner.as_deref().expect("owner lease is live")
    }
}

impl<T> Drop for OwnerLease<T> {
    fn drop(&mut self) {
        drop(self.owner.take());
        if let Ok(mut state) = self.entry.state.lock() {
            state.leases = state.leases.saturating_sub(1);
            if state.leases == 0 {
                self.entry.idle.notify_all();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OwnerEntry;
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn close_cannot_ack_until_the_last_in_flight_owner_lease_is_released() {
        let dropped = Arc::new(AtomicBool::new(false));
        let entry = Arc::new(OwnerEntry::new(DropProbe(dropped.clone())));
        let lease = entry.acquire().expect("owner call starts before close");

        assert!(!entry.close(Duration::from_millis(20)));
        assert!(!dropped.load(Ordering::SeqCst));
        assert!(
            entry.acquire().is_err(),
            "closing fences every new owner call"
        );

        drop(lease);
        for _ in 0..100 {
            if dropped.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            dropped.load(Ordering::SeqCst),
            "the retained owner is destroyed only after its final lease"
        );
    }

    #[test]
    fn retained_owner_prevents_a_successful_close_ack_until_release() {
        let dropped = Arc::new(AtomicBool::new(false));
        let entry = Arc::new(OwnerEntry::new(DropProbe(dropped.clone())));
        let lease = entry.acquire().expect("owner call starts before close");
        let closer = entry.clone();
        let (result, acknowledgement) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = result.send(closer.close(Duration::from_secs(1)));
        });

        for _ in 0..100 {
            if entry.acquire().is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(entry.acquire().is_err(), "close must fence new calls");
        assert!(acknowledgement
            .recv_timeout(Duration::from_millis(20))
            .is_err());
        assert!(!dropped.load(Ordering::SeqCst));

        drop(lease);
        assert!(acknowledgement
            .recv_timeout(Duration::from_secs(1))
            .expect("close must ACK after the retained owner is released"));
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn close_ack_means_the_owner_was_actually_destroyed() {
        let dropped = Arc::new(AtomicBool::new(false));
        let entry = Arc::new(OwnerEntry::new(DropProbe(dropped.clone())));

        assert!(entry.close(Duration::from_secs(1)));
        assert!(dropped.load(Ordering::SeqCst));
        assert!(entry.acquire().is_err());
    }
}
