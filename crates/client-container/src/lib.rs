//! Container-owned authentication. Runtime integration is a separate boundary.
mod auth_broker;
mod cleanup;
pub mod host;
mod host_updater;
mod installed_runtime;
pub mod ipc;
mod runtime_auth;
mod selection;
mod switch;
mod update;
pub use auth_broker::*;
pub use cleanup::*;
pub use runtime_auth::*;
pub use selection::*;
pub use switch::*;
pub use update::*;
