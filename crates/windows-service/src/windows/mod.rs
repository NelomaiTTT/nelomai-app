mod backend;
mod elevation;
mod install;
mod ipc;
mod routes;
mod service;

pub use elevation::{repair_installation, RepairError};
pub use install::{install, uninstall, InstallOptions};
pub use ipc::NamedPipeTransport;
pub use service::{run_amneziawg_service, run_manager_service, run_wireguard_service};

use crate::ServiceError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

pub(crate) fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

pub(crate) fn platform_error(context: &str, error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Backend(format!("{context}: {error}"))
}
