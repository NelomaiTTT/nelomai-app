use async_trait::async_trait;
use nelomai_client_core::CoreLocalStop;
use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStartRequest, TunnelStatus};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
struct Tunnel {
    protection: Option<bool>,
    explicit: AtomicUsize,
    scoped: AtomicUsize,
}
#[async_trait]
impl TunnelController for Tunnel {
    async fn start(&self, _: TunnelStartRequest) -> Result<(), TunnelError> {
        panic!("no Start")
    }
    async fn stop(&self) -> Result<(), TunnelError> {
        self.explicit.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn stop_if_unowned(&self) -> Result<(), TunnelError> {
        self.scoped.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn status(&self) -> Result<TunnelStatus, TunnelError> {
        Ok(TunnelStatus::Stopped)
    }
    async fn retains_protection(&self) -> Result<bool, TunnelError> {
        self.protection
            .ok_or_else(|| TunnelError::Backend("status_unavailable".into()))
    }
}
#[tokio::test]
async fn channel_loss_preserves_retained_or_uncertain_protection_but_explicit_stop_releases_it() {
    for protection in [Some(true), None, Some(false)] {
        let tunnel = Arc::new(Tunnel {
            protection,
            explicit: AtomicUsize::new(0),
            scoped: AtomicUsize::new(0),
        });
        let local = CoreLocalStop::new(tunnel.clone());
        local.stop_local_on_disconnect().await.unwrap();
        let preserve = protection != Some(false);
        assert_eq!(
            tunnel.explicit.load(Ordering::SeqCst),
            usize::from(!preserve)
        );
        assert_eq!(tunnel.scoped.load(Ordering::SeqCst), usize::from(preserve));
        local.stop_local_for_transition().await.unwrap();
        assert_eq!(
            tunnel.explicit.load(Ordering::SeqCst),
            usize::from(!preserve) + 1
        );
        local.stop_local().await.unwrap();
        assert_eq!(
            tunnel.explicit.load(Ordering::SeqCst),
            usize::from(!preserve) + 2
        );
    }
}
