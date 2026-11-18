//! Native session composition. The health coordinator, not this route owner,
//! decides when a member is healthy. No GUI or IPC capability is enabled here.
use super::diagnostic::{DiagnosticJournal, DiagnosticNetwork, FailureSlot, PairFailure, Stage};
use super::members::SessionMembers;
use super::policy::PhysicalPolicyProvider;
use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend};
use nelomai_client_tunnel::redundancy::{
    driver::RouteRefreshError,
    network::*,
    route_plan::{tunnel_destinations_preserving, unix_member_route_plan},
    SessionScope, Slot,
};
use nelomai_contracts::RedundantHealthProbe;
use std::{collections::HashSet, net::IpAddr};

/// Resolved by the privileged physical-network adapter BEFORE starting a member.
/// Never accept interface indexes, gateways or DNS service names from app IPC.
#[derive(Clone, Debug)]
pub struct NetworkPolicy {
    /// Destinations left to the OS routing table, including the pinned peer endpoints.
    pub exclusions: Vec<ipnet::IpNet>,
    /// Existing OS route prefixes whose original priority must survive CIDR subtraction.
    pub existing: Vec<ipnet::IpNet>,
    /// Physical egress dependencies read from the kernel; never owned or written.
    pub retained_routes: Vec<RouteValue>,
    pub dns_services: Vec<String>,
    pub metric: u32,
}

pub struct SessionNetwork<B, N, S> {
    scope: SessionScope,
    members: SessionMembers<B>,
    network: NetworkOwner<DiagnosticNetwork<N>, DiagnosticJournal<S>>,
    failure: FailureSlot,
    policy: Option<NetworkPolicy>,
    dns: [Vec<IpAddr>; 2],
    endpoints: [Option<IpAddr>; 2],
    closing: bool,
    closing_incomplete: bool,
    retired_interfaces: [Option<u32>; 2],
}

impl<B: ServiceTunnelBackend, N: NetworkSystem, S: NetworkJournalStore> SessionNetwork<B, N, S> {
    pub fn new(
        scope: SessionScope,
        backends: [B; 2],
        system: N,
        store: S,
    ) -> Result<Self, ServiceError> {
        Ok(Self {
            members: SessionMembers::new(scope.clone(), backends)?,
            scope,
            network: NetworkOwner::fresh(DiagnosticNetwork(system), DiagnosticJournal(store)),
            failure: FailureSlot::default(),
            policy: None,
            dns: [Vec::new(), Vec::new()],
            endpoints: [None, None],
            closing: false,
            closing_incomplete: false,
            retired_interfaces: [None, None],
        })
    }
    pub(crate) fn begin_operation(&self) {
        self.failure.clear();
        self.members.failure.clear();
    }
    pub(crate) fn operation_error(&self, stage: Stage, error: ServiceError) -> std::io::Error {
        // close() returns the native failure first if both cleanup paths fail.
        let native = self.members.failure.take();
        let network = self.failure.take();
        native
            .or(network)
            .unwrap_or_else(|| PairFailure::service(stage, &error))
            .into_io(stage)
    }
    pub fn active(&self) -> Option<Slot> {
        if self.closing {
            None
        } else {
            self.network.active()
        }
    }
    /// The factory must load `journal` from its private scope-bound store. This
    /// path never resumes data routing or reports stale native health as Running.
    pub fn recover_for_cleanup(
        scope: SessionScope,
        backends: [B; 2],
        system: N,
        store: S,
        journal: NetworkJournal,
    ) -> Result<Self, ServiceError> {
        Ok(Self {
            members: SessionMembers::recover_for_cleanup(scope.clone(), backends)?,
            scope,
            network: NetworkOwner::recover(
                DiagnosticNetwork(system),
                DiagnosticJournal(store),
                journal.unix_recovery().map_err(network_error)?,
            )
            .map_err(network_error)?,
            failure: FailureSlot::default(),
            policy: None,
            dns: [Vec::new(), Vec::new()],
            endpoints: [None, None],
            closing: true,
            closing_incomplete: true,
            retired_interfaces: [None, None],
        })
    }
    pub fn cleanup_pending(&self) -> bool {
        self.closing_incomplete
            || self.retired_interfaces.iter().any(Option::is_some)
            || self.network.cleanup_pending()
            || (self.closing
                && (self.network.has_resources()
                    || [Slot::A, Slot::B]
                        .into_iter()
                        .any(|s| self.members.cleanup_needed(s))))
    }
    pub(crate) fn tick_member_backends(&mut self, now: u64) -> Result<(), ServiceError> {
        if self.closing || self.network.active().is_none() {
            return Ok(());
        }
        self.members.tick_backends(&self.scope, now)
    }

    pub fn members(&self) -> &SessionMembers<B> {
        &self.members
    }

    pub fn start_primary(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        config: &ParsedConfiguration,
        probe: RedundantHealthProbe,
        policy: NetworkPolicy,
    ) -> Result<(), ServiceError> {
        self.check(scope)?;
        if self.policy.is_some() {
            return Err(fenced());
        }
        self.members.validate_start(scope, slot, config, &probe)?;
        validate_policy(&policy)?;
        self.verify_retained(&policy)?;
        let endpoint = validate_endpoint(config, &policy.exclusions)?;
        validate_dns(&config.dns)?;
        tunnel_destinations_preserving(
            &config.peers[0].allowed_ips,
            &policy.exclusions,
            &policy.existing,
        )
        .map_err(|e| self.failure.network(Stage::Network, e))?;
        self.network
            .system_mut()
            .verify_physical_endpoint(endpoint, &policy.retained_routes)
            .map_err(|e| self.failure.network(Stage::Network, e))?;
        // Retain the policy even on partial native start. Only scoped Stop can
        // dispose of those resources; a new Start must not adopt their remnants.
        self.policy = Some(policy);
        self.dns[index(slot)] = config.dns.clone();
        self.endpoints[index(slot)] = Some(endpoint);
        let view = self.members.start(scope, slot, config, probe)?;
        self.network
            .system_mut()
            .member_started(slot, view.routes.interface)
            .map_err(|e| self.failure.network(Stage::Network, e))?;
        self.select_active(scope, slot)
    }

    pub fn add_standby(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        config: &ParsedConfiguration,
        probe: RedundantHealthProbe,
        policy: NetworkPolicy,
    ) -> Result<(), ServiceError> {
        self.check(scope)?;
        let active = self.active().ok_or_else(fenced)?;
        if slot == active || self.retired_interfaces[index(slot)].is_some() {
            return Err(fenced());
        }
        self.members.validate_start(scope, slot, config, &probe)?;
        let endpoint = validate_endpoint(config, &policy.exclusions)?;
        validate_dns(&config.dns)?;
        // Carve the candidate endpoint out of the current active routes before
        // its transport socket starts. Preserve every already attached endpoint.
        let (_, values) = self.plan_policy_routes(scope, &policy)?;
        tunnel_destinations_preserving(
            &config.peers[0].allowed_ips,
            &policy.exclusions,
            &policy.existing,
        )
        .map_err(|e| self.failure.network(Stage::Network, e))?;
        self.network
            .select(active, values)
            .map_err(|e| self.failure.network(Stage::Network, e))?;
        self.verify_committed_endpoints(&policy)
            .map_err(|e| self.failure.network(Stage::Network, e))?;
        let candidate_egress = self
            .network
            .system_mut()
            .verify_physical_endpoint(endpoint, &policy.retained_routes);
        self.policy = Some(policy);
        // The primary's committed routes were verified. A candidate with a
        // foreign transport path can be rejected before it acquires a backend.
        candidate_egress.map_err(|e| self.failure.network(Stage::Network, e))?;
        self.endpoints[index(slot)] = Some(endpoint);
        self.dns[index(slot)] = config.dns.clone();
        let view = self.members.start(scope, slot, config, probe)?;
        self.network
            .system_mut()
            .member_started(slot, view.routes.interface)
            .map_err(|e| self.failure.network(Stage::Network, e))?;
        // Same active and DNS: adding B only installs B's scoped probe route.
        self.select_active(scope, active)
    }

    /// Caller must supply current-epoch health evidence before promotion.
    pub fn select_active(&mut self, scope: &SessionScope, slot: Slot) -> Result<(), ServiceError> {
        self.check(scope)?;
        self.members.check_live(scope, slot)?;
        let policy = self.policy.clone().ok_or_else(fenced)?;
        let values = self.values(slot, &policy)?;
        self.network
            .select(slot, values)
            .map_err(|e| self.failure.network(Stage::Network, e))?;
        self.verify_committed_endpoints(&policy)
            .map_err(|e| self.failure.network(Stage::Network, e))
    }

    /// A failed reserve does not tear down a working primary. Remove only the
    /// inactive native member, then its probe routes, then its table binding.
    /// A journal/rollback conflict is returned to the owner, never hidden as a
    /// successful detach. Endpoint exclusions stay in the plan until the next physical policy discovery.
    pub fn remove_standby(&mut self, scope: &SessionScope, slot: Slot) -> Result<(), ServiceError> {
        self.check(scope)?;
        let active = self.active().ok_or_else(fenced)?;
        if active == slot {
            return Err(fenced());
        }
        let i = index(slot);
        if let Some(view) = self.members.view(slot) {
            self.retired_interfaces[i] = Some(view.routes.interface);
        }
        self.members.stop(scope, slot)?;
        if let Some(interface) = self.retired_interfaces[i] {
            self.network
                .confirm_link_closed(interface)
                .map_err(|e| self.failure.network(Stage::Network, e))?;
        }
        self.dns[i].clear();
        self.endpoints[i] = None;
        let policy = self.policy.clone().ok_or_else(fenced)?;
        let values = self.values(active, &policy)?;
        self.network
            .select(active, values)
            .map_err(|e| self.failure.network(Stage::Network, e))?;
        if let Some(interface) = self.retired_interfaces[i] {
            self.network
                .system_mut()
                .member_stopped(slot, interface)
                .map_err(|e| self.failure.network(Stage::Network, e))?;
            self.retired_interfaces[i] = None;
        }
        Ok(())
    }

    /// The coordinator invalidates all in-flight probes and health samples
    /// before invoking this operation. Verify the new physical path before rebinding.
    pub fn network_changed(
        &mut self,
        scope: &SessionScope,
        policy: NetworkPolicy,
    ) -> Result<(), ServiceError> {
        let (active, values) = self.plan_policy_routes(scope, &policy)?;
        self.network
            .select(active, values)
            .map_err(|e| self.failure.network(Stage::Network, e))?;
        self.verify_committed_endpoints(&policy)
            .map_err(|e| self.failure.network(Stage::Network, e))?;
        self.policy = Some(policy);
        self.members.rebind(scope)
    }

    pub(super) fn plan_policy_routes(
        &mut self,
        scope: &SessionScope,
        policy: &NetworkPolicy,
    ) -> Result<(Slot, Vec<NetworkValue>), ServiceError> {
        self.check(scope)?;
        validate_policy(policy)?;
        if self
            .endpoints
            .iter()
            .flatten()
            .any(|e| !policy.exclusions.contains(&ipnet::IpNet::from(*e)))
        {
            return Err(ServiceError::InvalidRequest);
        }
        let active = self.active().ok_or_else(fenced)?;
        Ok((active, self.values(active, policy)?))
    }

    pub(super) fn replace_policy_routes(
        &mut self,
        active: Slot,
        values: Vec<NetworkValue>,
        policy: NetworkPolicy,
    ) -> Result<(), RouteRefreshError> {
        self.network.select_with_outcome(active, values)?;
        self.verify_committed_endpoints(&policy)?;
        self.policy = Some(policy);
        Ok(())
    }

    pub fn close(&mut self, scope: &SessionScope) -> Result<(), ServiceError> {
        if &self.scope != scope {
            return Err(ServiceError::UnauthorizedClient);
        }
        self.closing = true;
        self.closing_incomplete = true;
        // Cut native traffic before potentially slow DNS/route cleanup. Still
        // attempt both paths on failure and retain their independent journals.
        let members = self.members.close(scope);
        let retired_routes = if members.is_ok() {
            self.network.confirm_links_closed()
        } else {
            Ok(())
        };
        let network = self
            .network
            .cleanup()
            .and(retired_routes)
            .map_err(|e| self.failure.network(Stage::Network, e));
        members.and(network)?;
        self.network
            .system_mut()
            .session_closed()
            .map_err(|e| self.failure.network(Stage::Network, e))?;
        self.closing_incomplete = false;
        self.retired_interfaces = [None, None];
        Ok(())
    }

    fn values(
        &mut self,
        active: Slot,
        policy: &NetworkPolicy,
    ) -> Result<Vec<NetworkValue>, ServiceError> {
        self.verify_retained(policy)?;
        let members = [Slot::A, Slot::B]
            .into_iter()
            .filter_map(|slot| {
                // A vanished old member must not prevent promotion by demanding a
                // new probe route to its nonexistent interface. Selected slot is
                // checked separately and may never be silently omitted.
                self.members.check_live(&self.scope, slot).ok()?;
                self.members.view(slot).map(|v| v.routes.clone())
            })
            .collect::<Vec<_>>();
        if policy
            .retained_routes
            .iter()
            .any(|r| members.iter().any(|m| m.interface == r.interface))
        {
            return Err(ServiceError::InvalidRequest);
        }
        let routes = unix_member_route_plan(
            active,
            &members,
            &policy.exclusions,
            &policy.existing,
            policy.metric,
        )
        .map_err(|e| self.failure.network(Stage::Network, e))?;
        let mut values = Vec::new();
        for route in routes {
            values.extend(
                self.network
                    .system_mut()
                    .route_resources(route)
                    .map_err(|e| self.failure.network(Stage::Network, e))?,
            );
        }
        if !self.dns[index(active)].is_empty() {
            let interface = self
                .members
                .view(active)
                .ok_or(ServiceError::InvalidRequest)?
                .routes
                .interface;
            values.extend(
                self.network
                    .system_mut()
                    .dns_resources(interface, &self.dns[index(active)], &policy.dns_services)
                    .map_err(|e| self.failure.network(Stage::Network, e))?,
            );
        }
        Ok(values)
    }
    fn verify_committed_endpoints(&mut self, policy: &NetworkPolicy) -> std::io::Result<()> {
        for endpoint in self.endpoints.into_iter().flatten() {
            if let Err(error) = self
                .network
                .system_mut()
                .verify_physical_endpoint(endpoint, &policy.retained_routes)
            {
                // Data routes have already changed. Never publish an active
                // tunnel or permit another mutation over unverified transport.
                self.closing = true;
                self.closing_incomplete = true;
                return Err(error);
            }
        }
        Ok(())
    }

    fn verify_retained(&mut self, policy: &NetworkPolicy) -> Result<(), ServiceError> {
        for route in &policy.retained_routes {
            if !self
                .network
                .system_mut()
                .verify_retained_route(route)
                .map_err(|e| self.failure.network(Stage::Network, e))?
            {
                return Err(ServiceError::Backend("physical_route_changed".into()));
            }
        }
        Ok(())
    }
    fn check(&self, scope: &SessionScope) -> Result<(), ServiceError> {
        if &self.scope != scope {
            return Err(ServiceError::UnauthorizedClient);
        }
        if self.closing || self.network.cleanup_pending() {
            return Err(fenced());
        }
        Ok(())
    }
}
impl<B: ServiceTunnelBackend, N: super::policy::PhysicalPolicyProvider, S: NetworkJournalStore>
    SessionNetwork<B, N, S>
{
    /// Read-only discovery before any primary member or session routes start.
    pub fn resolve_primary_policy(
        &mut self,
        scope: &SessionScope,
        options: &nelomai_client_tunnel::DesktopTunnelOptions,
        endpoint: IpAddr,
    ) -> Result<NetworkPolicy, ServiceError> {
        self.check(scope)?;
        if self.policy.is_some() || self.network.has_resources() {
            return Err(fenced());
        }
        self.resolve_policy(options, &[endpoint])
    }

    /// Discover against both installed endpoints before standby/network changes.
    pub fn resolve_updated_policy(
        &mut self,
        scope: &SessionScope,
        options: &nelomai_client_tunnel::DesktopTunnelOptions,
        extra_endpoint: Option<IpAddr>,
    ) -> Result<NetworkPolicy, ServiceError> {
        self.check(scope)?;
        if self.active().is_none() {
            return Err(fenced());
        }
        let mut endpoints = self
            .endpoints
            .iter()
            .flatten()
            .copied()
            .chain(extra_endpoint)
            .collect::<Vec<_>>();
        endpoints.sort();
        endpoints.dedup();
        self.resolve_policy(options, &endpoints)
    }

    fn resolve_policy(
        &mut self,
        options: &nelomai_client_tunnel::DesktopTunnelOptions,
        endpoints: &[IpAddr],
    ) -> Result<NetworkPolicy, ServiceError> {
        options
            .validate()
            .map_err(|_| ServiceError::InvalidRequest)?;
        if endpoints.is_empty() || endpoints.len() > 2 {
            return Err(ServiceError::InvalidRequest);
        }
        // Only the durable owner may identify routes excluded from discovery.
        // User policy exclusions remain options, never ownership evidence.
        let owned = self.network.excluded_routes();
        self.network
            .system_mut()
            .resolve_policy(options, endpoints, &owned)
            .map_err(|e| self.failure.network(Stage::Network, e))
    }
}

pub(super) fn expected_egress(
    endpoint: IpAddr,
    retained: &[RouteValue],
) -> std::io::Result<&RouteValue> {
    retained
        .iter()
        .filter(|r| r.scope == RouteScope::Global && r.destination.contains(&endpoint))
        .max_by_key(|r| (r.destination.prefix_len(), std::cmp::Reverse(r.metric)))
        .ok_or_else(|| std::io::Error::other("physical_egress_unavailable"))
}

fn index(slot: Slot) -> usize {
    match slot {
        Slot::A => 0,
        Slot::B => 1,
    }
}
fn fenced() -> ServiceError {
    ServiceError::Backend("member_session_fenced".into())
}
fn network_error(_: std::io::Error) -> ServiceError {
    ServiceError::Backend("member_network_failed".into())
}
fn validate_endpoint(
    config: &ParsedConfiguration,
    exclusions: &[ipnet::IpNet],
) -> Result<IpAddr, ServiceError> {
    let endpoint = config
        .peers
        .first()
        .ok_or(ServiceError::InvalidConfiguration)?
        .endpoint
        .host()
        .parse::<IpAddr>()
        .map_err(|_| ServiceError::InvalidConfiguration)?;
    // Native adapter must pin a resolved address in the member configuration;
    // otherwise DNS rotation could send encrypted packets through the other VPN.
    if !exclusions.contains(&ipnet::IpNet::from(endpoint)) {
        return Err(ServiceError::InvalidRequest);
    }
    Ok(endpoint)
}
fn validate_policy(policy: &NetworkPolicy) -> Result<(), ServiceError> {
    let mut seen = HashSet::new();
    if policy.exclusions.len() > 16_384 || policy.retained_routes.len() > 16_384
        || policy.exclusions.iter().any(|n| *n != n.trunc())
        || policy.dns_services.len() > 64
        || policy.retained_routes.iter()
            .any(|r| {
                r.interface == 0
                    || !(r.scope == RouteScope::Global
                        || matches!(r.scope, RouteScope::Member(i)
                            if i == r.interface && r.destination.prefix_len() == 0 && r.metric == 0))
                    || r.destination != r.destination.trunc()
                    || r.gateway
                        .is_some_and(|g| g.is_ipv4() != r.destination.addr().is_ipv4())
                    || !seen.insert((r.destination, r.scope))
            })
    {
        return Err(ServiceError::InvalidRequest);
    }
    let mut names = HashSet::new();
    if policy.dns_services.iter().any(|s| {
        s.is_empty() || s.len() > 256 || s.chars().any(char::is_control) || !names.insert(s)
    }) {
        return Err(ServiceError::InvalidRequest);
    }
    Ok(())
}
fn validate_dns(servers: &[IpAddr]) -> Result<(), ServiceError> {
    if servers.len() > 16
        || servers
            .iter()
            .any(|s| s.is_unspecified() || s.is_multicast())
    {
        return Err(ServiceError::InvalidConfiguration);
    }
    Ok(())
}
