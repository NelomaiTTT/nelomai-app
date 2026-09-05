#[path = "../../../client-core/tests/support/mod.rs"]
mod auth;
pub use auth::*;
use nelomai_client_application::{ApplicationApi, ClientApplication};
use nelomai_client_core::{CoreLocalStop, CoreLogger};
use nelomai_client_storage::SecretStore;
use nelomai_client_tunnel::TunnelController;
use std::sync::Arc;

pub fn application<
    A: ApplicationApi + TestAuthApi + 'static,
    S: SecretStore + 'static,
    T: TunnelController + 'static,
    L: CoreLogger,
>(
    api: Arc<A>,
    store: Arc<S>,
    tunnel: Arc<T>,
    logger: Arc<L>,
) -> ClientApplication<A, LegacyRuntime<S>, T, L> {
    let local = CoreLocalStop::new(tunnel);
    let auth = Arc::new(TestOwner::new(api.clone(), store.clone(), local.clone()));
    ClientApplication::new(
        api,
        Arc::new(LegacyRuntime::new(store)),
        auth,
        local,
        logger,
    )
}
