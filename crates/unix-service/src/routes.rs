#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod linux;
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod macos;

use crate::ServiceError;
use ipnet::Ipv4Net;
use nelomai_client_tunnel::{DesktopTunnelOptions, Ipv4RoutePlan};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    #[serde(default)]
    pub pending_routes: Vec<OwnedRoute>,
}

impl fmt::Debug for OwnedRouteState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedRouteState")
            .field("format_version", &self.format_version)
            .field("policy_hash_present", &self.policy_hash.is_some())
            .field("routes_count", &self.routes.len())
            .field("pending_routes_count", &self.pending_routes.len())
            .finish()
    }
}

pub(crate) trait RouteBackend {
    type Egress;

    fn discover_egress(&self) -> Result<Self::Egress, ServiceError>;
    fn local_networks(&self, egress: &Self::Egress) -> Result<Vec<Ipv4Net>, ServiceError>;
    fn fingerprint_material(&self, egress: &Self::Egress, local_networks: &[Ipv4Net]) -> String;
    fn owned_route(&self, egress: &Self::Egress, network: Ipv4Net) -> OwnedRoute;
    fn route_exists(&self, route: &OwnedRoute) -> Result<bool, ServiceError>;
    fn route_presence(&self, routes: &[OwnedRoute]) -> Result<Vec<bool>, ServiceError> {
        routes
            .iter()
            .map(|route| self.route_exists(route))
            .collect()
    }
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
        if plan.excluded_networks.is_empty() {
            return Ok(());
        }

        let egress = self.backend.discover_egress()?;
        let routes = plan
            .excluded_networks
            .into_iter()
            .map(|network| self.backend.owned_route(&egress, network))
            .collect::<Vec<_>>();
        if self
            .backend
            .route_presence(&routes)?
            .into_iter()
            .any(|exists| exists)
        {
            return Err(ServiceError::Backend("route_conflict".to_string()));
        }
        self.state.policy_hash = plan.policy_hash;
        self.state.pending_routes = routes.clone();
        self.persist()?;

        let mut applied = Vec::with_capacity(routes.len());
        for route in &routes {
            if let Err(error) = self.backend.add_route(route) {
                self.state.routes = applied;
                self.state.pending_routes.clear();
                let _ = self.persist();
                let _ = self.cleanup();
                return Err(error);
            }
            applied.push(route.clone());
        }
        self.state.routes = applied;
        self.state.pending_routes.clear();
        if let Err(error) = self.persist() {
            let _ = self.cleanup();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), ServiceError> {
        let mut first_error = None;
        let routes = std::mem::take(&mut self.state.routes);
        self.state.routes = self.remove_present_routes(routes, &mut first_error);
        let pending_routes = std::mem::take(&mut self.state.pending_routes);
        self.state.pending_routes = self.remove_present_routes(pending_routes, &mut first_error);
        if self.state.routes.is_empty() && self.state.pending_routes.is_empty() {
            self.state.policy_hash = None;
            remove_state(&self.state_path)?;
        } else {
            self.persist()?;
        }
        first_error.map_or(Ok(()), Err)
    }

    fn remove_present_routes(
        &self,
        routes: Vec<OwnedRoute>,
        first_error: &mut Option<ServiceError>,
    ) -> Vec<OwnedRoute> {
        if routes.is_empty() {
            return Vec::new();
        }
        let presence = match self.backend.route_presence(&routes) {
            Ok(presence) if presence.len() == routes.len() => presence,
            Ok(_) => {
                first_error.get_or_insert_with(|| {
                    ServiceError::Backend("route_table_unavailable".to_string())
                });
                return routes;
            }
            Err(error) => {
                first_error.get_or_insert(error);
                return routes;
            }
        };
        let mut retained = Vec::new();
        for (route, exists) in routes.into_iter().zip(presence) {
            if exists {
                if let Err(error) = self.backend.remove_route(&route) {
                    first_error.get_or_insert(error);
                    retained.push(route);
                }
            }
        }
        retained
    }

    pub(crate) fn has_routes(&self) -> bool {
        !self.state.routes.is_empty() || !self.state.pending_routes.is_empty()
    }

    pub(crate) fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        let egress = self.backend.discover_egress()?;
        let mut local_networks = self.backend.local_networks(&egress)?;
        local_networks.sort_unstable();
        local_networks.dedup();
        let material = self.backend.fingerprint_material(&egress, &local_networks);
        let digest = Sha256::digest(material.as_bytes());
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn persist(&self) -> Result<(), ServiceError> {
        if self
            .state
            .routes
            .len()
            .saturating_add(self.state.pending_routes.len())
            > MAX_ROUTES
        {
            return Err(ServiceError::Backend("route_state_too_large".to_string()));
        }
        let bytes = serde_json::to_vec(&self.state)
            .map_err(|_| ServiceError::Backend("route_state_serialize_failed".to_string()))?;
        if bytes.len() as u64 > MAX_STATE_SIZE {
            return Err(ServiceError::Backend("route_state_too_large".to_string()));
        }
        let temporary = self.state_path.with_extension("json.new");
        remove_stale_temporary(&temporary)?;
        let mut file = OpenOptions::new()
            .create_new(true)
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
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_STATE_SIZE
    {
        return Err(ServiceError::Backend("route_state_invalid".to_string()));
    }
    let bytes =
        fs::read(path).map_err(|_| ServiceError::Backend("route_state_read_failed".to_string()))?;
    let state: OwnedRouteState = serde_json::from_slice(&bytes)
        .map_err(|_| ServiceError::Backend("route_state_invalid".to_string()))?;
    if state.format_version != ROUTE_STATE_FORMAT
        || state
            .routes
            .len()
            .saturating_add(state.pending_routes.len())
            > MAX_ROUTES
    {
        return Err(ServiceError::Backend("route_state_invalid".to_string()));
    }
    Ok(state)
}

fn remove_stale_temporary(path: &Path) -> Result<(), ServiceError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(ServiceError::Backend(
                "route_state_write_failed".to_string(),
            ))
        }
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(ServiceError::Backend(
            "route_state_write_failed".to_string(),
        ));
    }
    fs::remove_file(path).map_err(|_| ServiceError::Backend("route_state_write_failed".to_string()))
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
        installed: RefCell<Vec<String>>,
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

        fn fingerprint_material(
            &self,
            _egress: &Self::Egress,
            local_networks: &[Ipv4Net],
        ) -> String {
            format!("fake\0{local_networks:?}")
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
                self.installed.borrow_mut().push(route.destination.clone());
                Ok(())
            }
        }

        fn route_exists(&self, route: &OwnedRoute) -> Result<bool, ServiceError> {
            Ok(self
                .installed
                .borrow()
                .iter()
                .any(|destination| destination == &route.destination))
        }

        fn remove_route(&self, route: &OwnedRoute) -> Result<(), ServiceError> {
            self.removed.borrow_mut().push(route.destination.clone());
            self.installed
                .borrow_mut()
                .retain(|destination| destination != &route.destination);
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
        assert_eq!(
            manager.backend.removed.borrow().as_slice(),
            ["203.0.113.0/24"]
        );
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

        assert_eq!(error.code(), "route_add_failed");
        assert!(!manager.has_routes());
        assert!(!directory.path().join(ROUTE_STATE_FILE).exists());
        assert_eq!(
            manager.backend.removed.borrow().as_slice(),
            ["198.51.100.0/24"]
        );
    }

    #[test]
    fn recovery_does_not_remove_a_pending_route_that_was_never_installed() {
        let directory = tempfile::tempdir().unwrap();
        let mut manager = RouteManager::new(directory.path(), FakeBackend::default()).unwrap();
        manager.state.pending_routes = vec![manager
            .backend
            .owned_route(&(), "203.0.113.0/24".parse().unwrap())];
        manager.persist().unwrap();

        manager.cleanup().unwrap();

        assert!(manager.backend.removed.borrow().is_empty());
        assert!(!manager.has_routes());
        assert!(!directory.path().join(ROUTE_STATE_FILE).exists());
    }

    #[test]
    fn recovery_does_not_remove_a_committed_route_that_no_longer_matches() {
        let directory = tempfile::tempdir().unwrap();
        let mut manager = RouteManager::new(directory.path(), FakeBackend::default()).unwrap();
        manager.state.routes = vec![manager
            .backend
            .owned_route(&(), "203.0.113.0/24".parse().unwrap())];
        manager.persist().unwrap();

        manager.cleanup().unwrap();

        assert!(manager.backend.removed.borrow().is_empty());
        assert!(!manager.has_routes());
        assert!(!directory.path().join(ROUTE_STATE_FILE).exists());
    }

    #[test]
    fn recovery_removes_a_pending_route_that_reached_the_route_table() {
        let directory = tempfile::tempdir().unwrap();
        let mut manager = RouteManager::new(directory.path(), FakeBackend::default()).unwrap();
        let route = manager
            .backend
            .owned_route(&(), "203.0.113.0/24".parse().unwrap());
        manager.backend.add_route(&route).unwrap();
        manager.state.pending_routes = vec![route];
        manager.persist().unwrap();

        manager.cleanup().unwrap();

        assert_eq!(
            manager.backend.removed.borrow().as_slice(),
            ["203.0.113.0/24"]
        );
        assert!(!manager.has_routes());
    }

    #[test]
    fn physical_network_fingerprint_is_stable_and_opaque() {
        let directory = tempfile::tempdir().unwrap();
        let manager = RouteManager::new(directory.path(), FakeBackend::default()).unwrap();

        let fingerprint = manager.physical_network_fingerprint().unwrap();

        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!fingerprint.contains("192.168.1.0"));
    }

    #[test]
    fn existing_local_networks_are_not_installed_as_owned_routes() {
        let directory = tempfile::tempdir().unwrap();
        let mut manager = RouteManager::new(directory.path(), FakeBackend::default()).unwrap();

        manager
            .apply(&DesktopTunnelOptions {
                excluded_ipv4_cidrs: Vec::new(),
                exclude_local_networks: true,
                policy_hash: Some("sha256:test".to_string()),
            })
            .unwrap();

        assert!(!manager.has_routes());
        assert!(!directory.path().join(ROUTE_STATE_FILE).exists());
    }

    #[test]
    fn state_file_with_group_permissions_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join(ROUTE_STATE_FILE);
        fs::write(
            &state_path,
            br#"{"format_version":1,"policy_hash":null,"routes":[]}"#,
        )
        .unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o640)).unwrap();

        let error = match RouteManager::new(directory.path(), FakeBackend::default()) {
            Ok(_) => panic!("unsafe state permissions must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.code(), "route_state_invalid");
    }
}
