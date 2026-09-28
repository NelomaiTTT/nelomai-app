//! Native route/DNS operations for the session owner, separate from either slot.
//! This module does not start tunnels or activate the feature on its own.
pub mod actor;
pub mod counters;
mod diagnostic;
pub mod driver;
#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub mod factory;
#[cfg(test)]
mod factory_tests;
pub mod journal;
#[cfg(any(target_os = "linux", test))]
pub mod linux;
#[cfg(any(target_os = "macos", test))]
pub mod macos;
pub mod members;
pub mod policy;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod runtime;
pub mod runtime_directory;
pub mod session;
