//! Container-owned authentication. Runtime integration is a separate boundary.
mod auth_broker;
mod runtime_auth;
pub use auth_broker::*;
pub use runtime_auth::*;
