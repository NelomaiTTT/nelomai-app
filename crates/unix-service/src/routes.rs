#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use crate::ServiceError;
use ipnet::Ipv4Net;
use nelomai_client_tunnel::{DesktopTunnelOptions, Ipv4RoutePlan};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
pub(crate) use linux::SystemRouteBackend;
#[cfg(target_os = "macos")]
pub(crate) use macos::SystemRouteBackend;

const ROUTE_STATE_FILE: &str = "routes-state.json";
const ROUTE_STATE_FORMAT: u16 = 1;
const MAX_STATE_SIZE: u64 = 4 * 1024 * 1024;
const MAX_ROUTES: usize = 16_384;

#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct OwnedRoute {
    pub destination: String,
    pub interface_identifier: String,
    pub gateway: Option<String>,
    pub metric: Option<u32>,
}

impl fmt::Debug for OwnedRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedRoute(<redacted>)")
    }
}

#[derive(Clone, Default, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct OwnedRouteState {
    pub format_version: u16,
    pub policy_hash: Option<String>,
    pub routes: Vec<OwnedRoute>,
}

impl fmt::Debug for OwnedRouteState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedRouteState")
            .field("format_version", &self.format_version)
            .field("policy_hash_present", &self.policy_hash.is_some())
            .field("routes_count", &self.routes.len())
            .finish()
    }
}

pub(crate) trait RouteBackend {
    type Egress;

    fn discover_egress(&self) -> Result<Self::Egress, ServiceError>;
    fn local_networks(&self, egress: &Self::Egress) -> Result<Vec<Ipv4Net>, ServiceError>;
    fn owned_route(&self, egress: &Self::Egress, network: Ipv4Net) -> OwnedRoute;
    fn add_route(&self, route: &OwnedRoute) -> Result<(), ServiceError>;
    fn remove_route(&self, route: &OwnedRoute) -> Result<(), ServiceError>;
}

pub(crate) struct RouteManager<B> {
    backend: B,
    state_path: PathBuf,
    state: OwnedRouteState,
}

impl<B: RouteBackend> RouteManager<B> {
    pub(crate) fn new(
        runtime_directory: impl AsRef<Path>,
        backend: B,
    ) -> Result<Self, ServiceError> {
        let state_path = runtime_directory.as_ref().join(ROUTE_STATE_FILE);
        let state = load_state(&state_path)?;
        Ok(Self {
            backend,
            state_path,
            state,
        })
    }

    pub(crate) fn apply(&mut self, options: &DesktopTunnelOptions) -> Result<(), ServiceError> {
        self.cleanup()?;
        let plan = Ipv4RoutePlan::from_options(options)
            .map_err(|error| ServiceError::Backend(error.stable_code().to_string()))?;
        if !plan.active() {
            return Ok(());
        }

        let egress = self.backend.discover_egress()?;
        let local = if plan.exclude_local_networks {
            self.backend.local_networks(&egress)?
        } else {
            Vec::new()
        };
        let plan = plan
            .merged_with_local_networks(local)
            .map_err(|error| ServiceError::Backend(error.stable_code().to_string()))?;
        self.state.policy_hash = plan.policy_hash;
        self.persist()?;

        for network in plan.excluded_networks {
            let route = self.backend.owned_route(&egress, network);
            self.state.routes.push(route.clone());
            if let Err(error) = self.persist() {
                let _ = self.cleanup();
                return Err(error);
            }
            if let Err(error) = self.backend.add_route(&route) {
                self.state.routes.pop();
                let _ = self.persist();
                let _ = self.cleanup();
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), ServiceError> {
        let mut first_error = None;
        let mut retained = Vec::new();
        for route in std::mem::take(&mut self.state.routes) {
            if let Err(error) = self.backend.remove_route(&route) {
                first_error.get_or_insert(error);
                retained.push(route);
            }
        }
        self.state.routes = retained;
        if self.state.routes.is_empty() {
            self.state.policy_hash = None;
            remove_state(&self.state_path)?;
        } else {
            self.persist()?;
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(crate) fn has_routes(&self) -> bool {
        !self.state.routes.is_empty()
    }

    fn persist(&self) -> Result<(), ServiceError> {
        if self.state.routes.len() > MAX_ROUTES {
            return Err(ServiceError::Backend("route_state_too_large".to_string()));
        }
        let bytes = serde_json::to_vec(&self.state)
            .map_err(|_| ServiceError::Backend("route_state_serialize_failed".to_string()))?;
        if bytes.len() as u64 > MAX_STATE_SIZE {
            return Err(ServiceError::Backend("route_state_too_large".to_string()));
        }
        let temporary = self.state_path.with_extension("json.new");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| ServiceError::Backend("route_state_write_failed".to_string()))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| ServiceError::Backend("route_state_write_failed".to_string()))?;
        fs::rename(&temporary, &self.state_path)
            .map_err(|_| ServiceError::Backend("route_state_activate_failed".to_string()))
    }
}

fn load_state(path: &Path) -> Result<OwnedRouteState, ServiceError> {
    if !path.exists() {
        return Ok(OwnedRouteState {
            format_version: ROUTE_STATE_FORMAT,
            ..OwnedRouteState::default()
        });
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ServiceError::Backend("route_state_read_failed".to_string()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.len() > MAX_STATE_SIZE
    {
        return Err(ServiceError::Backend("route_state_invalid".to_string()));
    }
    let bytes =
        fs::read(path).map_err(|_| ServiceError::Backend("route_state_read_failed".to_string()))?;
    let state: OwnedRouteState = serde_json::from_slice(&bytes)
        .map_err(|_| ServiceError::Backend("route_state_invalid".to_string()))?;
    if state.format_version != ROUTE_STATE_FORMAT || state.routes.len() > MAX_ROUTES {
        return Err(ServiceError::Backend("route_state_invalid".to_string()));
    }
    Ok(state)
}

fn remove_state(path: &Path) -> Result<(), ServiceError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ServiceError::Backend(
            "route_state_remove_failed".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct FakeBackend {
        removed: RefCell<Vec<String>>,
        fail_add: Option<String>,
    }

    impl RouteBackend for FakeBackend {
        type Egress = ();

        fn discover_egress(&self) -> Result<Self::Egress, ServiceError> {
            Ok(())
        }

        fn local_networks(&self, _egress: &Self::Egress) -> Result<Vec<Ipv4Net>, ServiceError> {
            Ok(vec!["192.168.1.0/24".parse().unwrap()])
        }

        fn owned_route(&self, _egress: &Self::Egress, network: Ipv4Net) -> OwnedRoute {
            OwnedRoute {
                destination: network.to_string(),
                interface_identifier: "test0".to_string(),
                gateway: Some("192.168.1.1".to_string()),
                metric: Some(42),
            }
        }

        fn add_route(&self, route: &OwnedRoute) -> Result<(), ServiceError> {
            if self.fail_add.as_deref() == Some(route.destination.as_str()) {
                Err(ServiceError::Backend("route_add_failed".to_string()))
            } else {
                Ok(())
            }
        }

        fn remove_route(&self, route: &OwnedRoute) -> Result<(), ServiceError> {
            self.removed.borrow_mut().push(route.destination.clone());
            Ok(())
        }
    }

    #[test]
    fn manager_persists_and_exactly_cleans_owned_routes() {
        let directory = tempfile::tempdir().unwrap();
        let mut manager = RouteManager::new(directory.path(), FakeBackend::default()).unwrap();
        manager
            .apply(&DesktopTunnelOptions {
                excluded_ipv4_cidrs: vec!["203.0.113.0/24".to_string()],
                exclude_local_networks: true,
                policy_hash: Some("sha256:test".to_string()),
            })
            .unwrap();
        assert!(manager.has_routes());
        assert!(directory.path().join(ROUTE_STATE_FILE).exists());

        manager.cleanup().unwrap();
        assert!(!manager.has_routes());
        assert!(!directory.path().join(ROUTE_STATE_FILE).exists());
        assert_eq!(manager.backend.removed.borrow().len(), 2);
    }

    #[test]
    fn manager_keeps_persisted_routes_until_the_backend_decides_recovery() {
        let directory = tempfile::tempdir().unwrap();
        {
            let mut manager = RouteManager::new(directory.path(), FakeBackend::default()).unwrap();
            manager
                .apply(&DesktopTunnelOptions {
                    excluded_ipv4_cidrs: vec!["203.0.113.0/24".to_string()],
                    exclude_local_networks: false,
                    policy_hash: Some("sha256:test".to_string()),
                })
                .unwrap();
        }

        let recovered = RouteManager::new(directory.path(), FakeBackend::default()).unwrap();

        assert!(recovered.has_routes());
        assert!(recovered.backend.removed.borrow().is_empty());
    }

    #[test]
    fn failed_route_application_cleans_every_route_owned_by_the_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let backend = FakeBackend {
            fail_add: Some("203.0.113.0/24".to_string()),
            ..FakeBackend::default()
        };
        let mut manager = RouteManager::new(directory.path(), backend).unwrap();

        let error = manager
            .apply(&DesktopTunnelOptions {
                excluded_ipv4_cidrs: vec![
                    "198.51.100.0/24".to_string(),
                    "203.0.113.0/24".to_string(),
                ],
                exclude_local_networks: false,
                policy_hash: Some("sha256:test".to_string()),
            })
            .unwrap_err();

        assert_eq!(error.code(), "service_unavailable");
        assert!(!manager.has_routes());
        assert!(!directory.path().join(ROUTE_STATE_FILE).exists());
        assert_eq!(
            manager.backend.removed.borrow().as_slice(),
            ["198.51.100.0/24"]
        );
    }
}
