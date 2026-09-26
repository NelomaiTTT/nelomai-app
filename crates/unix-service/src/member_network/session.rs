//! Native session composition. The health coordinator, not this route owner,
//! decides when a member is healthy. No GUI or IPC capability is enabled here.
use super::members::SessionMembers;
use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend};
use nelomai_client_tunnel::redundancy::{
    network::*, route_plan::member_route_plan, SessionScope, Slot,
};
use nelomai_contracts::RedundantHealthProbe;
use std::{collections::HashSet, net::IpAddr};

/// Resolved by the privileged physical-network adapter BEFORE starting a member.
/// Never accept interface indexes, gateways or DNS service names from app IPC.
#[derive(Clone, Debug)]
pub struct NetworkPolicy {
    pub bypasses: Vec<RouteValue>,
    /// Existing physical LAN routes: verify but never adopt/mutate/clean them.
    pub retained_routes: Vec<RouteValue>,
    pub dns_services: Vec<String>,
    pub metric: u32,
}

pub struct SessionNetwork<B, N, S> {
    scope: SessionScope,
    members: SessionMembers<B>,
    network: NetworkOwner<N, S>,
    policy: Option<NetworkPolicy>,
    dns: [Vec<IpAddr>; 2],
    endpoints: [Option<IpAddr>; 2],
    closing: bool,
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
            network: NetworkOwner::fresh(system, store),
            policy: None,
            dns: [Vec::new(), Vec::new()],
            endpoints: [None, None],
            closing: false,
        })
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
            network: NetworkOwner::recover(system, store, journal).map_err(network_error)?,
            policy: None,
            dns: [Vec::new(), Vec::new()],
            endpoints: [None, None],
            closing: true,
        })
    }
    pub fn cleanup_pending(&self) -> bool {
        self.network.cleanup_pending()
            || (self.closing
                && (self.network.has_resources()
                    || [Slot::A, Slot::B]
                        .into_iter()
                        .any(|s| self.members.cleanup_needed(s))))
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
        let endpoint = validate_endpoint(config, &policy.bypasses, &policy.retained_routes)?;
        validate_dns(&config.dns)?;
        self.network
            .prepare(
                policy
                    .bypasses
                    .iter()
                    .cloned()
                    .map(NetworkValue::Route)
                    .collect(),
            )
            .map_err(network_error)?;
        // Retain the policy even on partial native start. Only scoped Stop can
        // dispose of those resources; a new Start must not adopt their remnants.
        self.policy = Some(policy);
        self.dns[index(slot)] = config.dns.clone();
        self.endpoints[index(slot)] = Some(endpoint);
        self.members.start(scope, slot, config, probe)?;
        self.select_active(scope, slot)
    }

    pub fn add_standby(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        config: &ParsedConfiguration,
        probe: RedundantHealthProbe,
        endpoint_bypass: RouteValue,
    ) -> Result<(), ServiceError> {
        self.check(scope)?;
        let active = self.active().ok_or_else(fenced)?;
        if slot == active {
            return Err(fenced());
        }
        self.members.validate_start(scope, slot, config, &probe)?;
        let endpoint = validate_endpoint(config, std::slice::from_ref(&endpoint_bypass), &[])?;
        validate_dns(&config.dns)?;
        let mut next = self.policy.clone().ok_or_else(fenced)?;
        if let Some(old) = next
            .bypasses
            .iter()
            .chain(&next.retained_routes)
            .find(|r| r.destination == endpoint_bypass.destination)
        {
            if old != &endpoint_bypass {
                return Err(ServiceError::InvalidRequest);
            }
        } else {
            let value = NetworkValue::Route(endpoint_bypass.clone());
            match self
                .network
                .system_mut()
                .read(&value.key())
                .map_err(network_error)?
            {
                None => next.bypasses.push(endpoint_bypass),
                Some(current) if current == value => next.retained_routes.push(endpoint_bypass),
                _ => return Err(ServiceError::Backend("physical_route_changed".into())),
            }
        }
        validate_policy(&next)?;
        let values = self.values(active, &next)?;
        self.network.select(active, values).map_err(network_error)?;
        self.policy = Some(next);
        self.dns[index(slot)] = config.dns.clone();
        self.endpoints[index(slot)] = Some(endpoint);
        self.members.start(scope, slot, config, probe)?;
        // Same active and DNS: adding B only installs B's scoped probe route.
        self.select_active(scope, active)
    }

    /// Caller must supply current-epoch health evidence before promotion.
    pub fn select_active(&mut self, scope: &SessionScope, slot: Slot) -> Result<(), ServiceError> {
        self.check(scope)?;
        self.members.check_live(scope, slot)?;
        let policy = self.policy.clone().ok_or_else(fenced)?;
        let values = self.values(slot, &policy)?;
        self.network.select(slot, values).map_err(network_error)
    }

    /// The coordinator invalidates all in-flight probes and health samples
    /// before invoking this operation. Rebind must never precede bypass repair.
    pub fn network_changed(
        &mut self,
        scope: &SessionScope,
        policy: NetworkPolicy,
    ) -> Result<(), ServiceError> {
        self.check(scope)?;
        validate_policy(&policy)?;
        if self.endpoints.iter().flatten().any(|endpoint| {
            !has_endpoint(*endpoint, &policy.bypasses)
                && !has_endpoint(*endpoint, &policy.retained_routes)
        }) {
            return Err(ServiceError::InvalidRequest);
        }
        let active = self.active().ok_or_else(fenced)?;
        let values = self.values(active, &policy)?;
        self.network.select(active, values).map_err(network_error)?;
        self.policy = Some(policy);
        self.members.rebind(scope)
    }

    pub fn close(&mut self, scope: &SessionScope) -> Result<(), ServiceError> {
        if &self.scope != scope {
            return Err(ServiceError::UnauthorizedClient);
        }
        self.closing = true;
        // Cut native traffic before potentially slow DNS/route cleanup. Still
        // attempt both paths on failure and retain their independent journals.
        let members = self.members.close(scope);
        let network = self.network.cleanup().map_err(network_error);
        members.and(network)
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
            .bypasses
            .iter()
            .chain(&policy.retained_routes)
            .any(|r| members.iter().any(|m| m.interface == r.interface))
        {
            return Err(ServiceError::InvalidRequest);
        }
        let exclusions = policy
            .bypasses
            .iter()
            .chain(&policy.retained_routes)
            .map(|r| r.destination)
            .collect::<Vec<_>>();
        let routes = member_route_plan(active, &members, &exclusions, policy.metric)
            .map_err(network_error)?;
        let mut values = policy
            .bypasses
            .iter()
            .cloned()
            .map(NetworkValue::Route)
            .collect::<Vec<_>>();
        for route in routes {
            values.extend(
                self.network
                    .system_mut()
                    .route_resources(route)
                    .map_err(network_error)?,
            );
        }
        if !self.dns[index(active)].is_empty() {
            values.extend(policy.dns_services.iter().map(|service| {
                NetworkValue::Dns(DnsValue {
                    service: service.clone(),
                    servers: self.dns[index(active)].clone(),
                })
            }));
        }
        Ok(values)
    }
    fn verify_retained(&mut self, policy: &NetworkPolicy) -> Result<(), ServiceError> {
        for route in &policy.retained_routes {
            let value = NetworkValue::Route(route.clone());
            if self
                .network
                .system_mut()
                .read(&value.key())
                .map_err(network_error)?
                != Some(value)
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
    bypasses: &[RouteValue],
    retained: &[RouteValue],
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
    if !has_endpoint(endpoint, bypasses) && !has_endpoint(endpoint, retained) {
        return Err(ServiceError::InvalidRequest);
    }
    Ok(endpoint)
}
fn has_endpoint(endpoint: IpAddr, bypasses: &[RouteValue]) -> bool {
    bypasses
        .iter()
        .any(|r| r.destination == ipnet::IpNet::from(endpoint) && r.scope == RouteScope::Global)
}
fn validate_policy(policy: &NetworkPolicy) -> Result<(), ServiceError> {
    let mut seen = HashSet::new();
    if policy
        .bypasses
        .len()
        .saturating_add(policy.retained_routes.len())
        > 16384
        || policy.dns_services.len() > 64
        || policy
            .bypasses
            .iter()
            .chain(&policy.retained_routes)
            .any(|r| {
                r.interface == 0
                    || r.scope != RouteScope::Global
                    || r.destination != r.destination.trunc()
                    || r.gateway
                        .is_some_and(|g| g.is_ipv4() != r.destination.addr().is_ipv4())
                    || !seen.insert(r.destination)
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
