use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use nelomai_client_tunnel::{
    redundancy::{route_plan::MemberRoutes, NativeProbeSocket, SessionScope, Slot},
    DesktopTunnelOptions, TunnelMetrics,
};
use nelomai_contracts::RedundantHealthProbe;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug)]
pub struct MemberView {
    pub routes: MemberRoutes,
    pub source: Ipv4Addr,
    pub probe: RedundantHealthProbe,
    pub addresses: Vec<ipnet::IpNet>,
}

/// Serialized owner of two already independently configured native backends.
/// The enclosing session owns routes/DNS and must install physical endpoint
/// bypasses before calling start. Neither backend may be a single-mode backend.
pub struct SessionMembers<B> {
    scope: SessionScope,
    backends: [B; 2],
    needs_cleanup: [bool; 2],
    views: [Option<MemberView>; 2],
    closing: bool,
}
impl<B: ServiceTunnelBackend> SessionMembers<B> {
    pub fn new(scope: SessionScope, backends: [B; 2]) -> Result<Self, ServiceError> {
        if backends
            .iter()
            .any(ServiceTunnelBackend::member_cleanup_pending)
        {
            return Err(ServiceError::Backend("member_recovery_required".into()));
        }
        Self::construct(scope, backends, false)
    }
    /// Restart recovery deliberately exposes cleanup only, never old health or
    /// Running. Native constructors verify actual identities before this call.
    pub fn recover_for_cleanup(
        scope: SessionScope,
        backends: [B; 2],
    ) -> Result<Self, ServiceError> {
        if backends
            .iter()
            .any(|b| b.member_recovery_scope().as_ref() != Some(&scope))
        {
            return Err(ServiceError::UnauthorizedClient);
        }
        Self::construct(scope, backends, true)
    }
    fn construct(
        scope: SessionScope,
        backends: [B; 2],
        closing: bool,
    ) -> Result<Self, ServiceError> {
        if !scope.validate() {
            return Err(ServiceError::InvalidRequest);
        }
        use nelomai_contracts::dispatcher::TunnelSlot;
        if backends[0].member_slot() != Some(TunnelSlot::A)
            || backends[1].member_slot() != Some(TunnelSlot::B)
        {
            return Err(ServiceError::Backend(
                "member_backend_scope_mismatch".into(),
            ));
        }
        if backends
            .iter()
            .any(|b| b.member_recovery_scope().is_some_and(|s| s != scope))
        {
            return Err(ServiceError::UnauthorizedClient);
        }
        let needs_cleanup = backends
            .each_ref()
            .map(ServiceTunnelBackend::member_cleanup_pending);
        Ok(Self {
            scope,
            backends,
            needs_cleanup,
            views: [None, None],
            closing,
        })
    }
    pub fn cleanup_needed(&self, slot: Slot) -> bool {
        self.needs_cleanup[index(slot)]
    }
    pub fn view(&self, slot: Slot) -> Option<&MemberView> {
        self.views[index(slot)].as_ref()
    }

    pub fn scope(&self) -> &SessionScope {
        &self.scope
    }

    pub fn data_counters(
        &self,
        scope: &SessionScope,
        slot: Slot,
    ) -> Result<super::counters::DataCounters, ServiceError> {
        self.check_live(scope, slot)?;
        let counters = self.backends[index(slot)].member_data_counters()?;
        self.check_live(scope, slot)?;
        Ok(counters)
    }

    pub fn start(
        &mut self,
        scope: &SessionScope,
        slot: Slot,
        config: &ParsedConfiguration,
        probe: RedundantHealthProbe,
    ) -> Result<MemberView, ServiceError> {
        let (source, addresses) = self.validate_start(scope, slot, config, &probe)?;
        let i = index(slot);
        self.needs_cleanup[i] = true; // Native start can fail after allocating an interface.
        if self.backends[i].start(config, &DesktopTunnelOptions::default())?
            != ServiceTunnelState::Running
        {
            return Err(ServiceError::Backend("member_start_incomplete".into()));
        }
        let interface = self.backends[i].member_interface_index()?;
        if interface == 0
            || self
                .views
                .iter()
                .flatten()
                .any(|v| v.routes.interface == interface)
        {
            return Err(ServiceError::Backend("member_interface_conflict".into()));
        }
        let view = MemberView {
            routes: MemberRoutes {
                slot,
                interface,
                allowed: config.peers[0].allowed_ips.clone(),
                probe: probe.target_ipv4,
            },
            source,
            probe,
            addresses,
        };
        self.views[i] = Some(view.clone());
        Ok(view)
    }

    pub fn validate_start(
        &self,
        scope: &SessionScope,
        slot: Slot,
        config: &ParsedConfiguration,
        probe: &RedundantHealthProbe,
    ) -> Result<(Ipv4Addr, Vec<ipnet::IpNet>), ServiceError> {
        self.check(scope)?;
        let i = index(slot);
        if self.closing || self.needs_cleanup[i] {
            return Err(ServiceError::Backend("member_start_fenced".into()));
        }
        // Use the contract's canonical query/timeout validation even for a
        // programmatically constructed value, before invoking the native side.
        let wire = serde_json::to_value(probe).map_err(|_| ServiceError::InvalidRequest)?;
        let probe: RedundantHealthProbe =
            serde_json::from_value(wire).map_err(|_| ServiceError::InvalidRequest)?;
        if probe.target_ipv4.is_unspecified()
            || probe.target_ipv4.is_loopback()
            || probe.target_ipv4.is_multicast()
            || probe.target_ipv4.is_broadcast()
        {
            return Err(ServiceError::InvalidRequest);
        }
        let sources = config
            .addresses
            .iter()
            .filter_map(|a| match a {
                ipnet::IpNet::V4(a) if a.prefix_len() == 32 => Some(a.addr()),
                _ => None,
            })
            .collect::<Vec<_>>();
        if config
            .addresses
            .iter()
            .any(|a| a.prefix_len() != if a.addr().is_ipv4() { 32 } else { 128 })
            || sources.len() != 1
            || sources[0].is_unspecified()
            || sources[0].is_loopback()
            || sources[0].is_multicast()
            || sources[0].is_broadcast()
            || config.peers.len() != 1
            || !config.peers[0]
                .allowed_ips
                .iter()
                .any(|n| n.contains(&IpAddr::V4(probe.target_ipv4)))
        {
            return Err(ServiceError::InvalidConfiguration);
        }
        let mut addresses = config.addresses.clone();
        addresses.sort();
        addresses.dedup();
        if self
            .views
            .iter()
            .flatten()
            .any(|v| v.addresses != addresses)
        {
            return Err(ServiceError::Backend(
                "member_virtual_address_mismatch".into(),
            ));
        }
        Ok((sources[0], addresses))
    }

    pub fn stop(&mut self, scope: &SessionScope, slot: Slot) -> Result<(), ServiceError> {
        self.check(scope)?;
        let i = index(slot);
        if !self.needs_cleanup[i] {
            return Ok(());
        }
        if self.backends[i].stop()? != ServiceTunnelState::Stopped {
            return Err(ServiceError::Backend("member_stop_pending".into()));
        }
        self.needs_cleanup[i] = false;
        self.views[i] = None;
        Ok(())
    }

    pub fn close(&mut self, scope: &SessionScope) -> Result<(), ServiceError> {
        self.check(scope)?;
        self.closing = true;
        let mut first = None;
        for slot in [Slot::A, Slot::B] {
            if let Err(e) = self.stop(scope, slot) {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }

    pub fn metrics(&self, scope: &SessionScope, slot: Slot) -> Result<TunnelMetrics, ServiceError> {
        self.check_live(scope, slot)?;
        let result = self.backends[index(slot)].metrics(false);
        self.check_live(scope, slot)?;
        result
    }

    /// The existing Unix provider hashes physical default egress and addresses
    /// on that physical NIC, not the pair's /1, probe or endpoint bypass routes.
    /// Linux member defaults are in private tables; macOS excludes utun defaults.
    /// Keep the frontend's existing IPv4 fingerprint semantics. Never use the
    /// unrelated single backend or manufacture an empty fingerprint on failure.
    /// Member liveness is deliberately not a prerequisite for this read-only
    /// discovery: a vanished VPN interface must reach driver health evaluation,
    /// not masquerade as physical network loss and suspend failover. This does
    /// not attest member ownership; probes, metrics and mutations keep their
    /// separate exact-identity fences.
    pub fn physical_network_fingerprint(
        &self,
        scope: &SessionScope,
        slot: Slot,
    ) -> Result<String, ServiceError> {
        self.check(scope)?;
        if self.closing || self.view(slot).is_none() {
            return Err(ServiceError::Backend("member_not_running".into()));
        }
        let fingerprint = self.backends[index(slot)].physical_network_fingerprint()?;
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(ServiceError::Backend(
                "physical_network_fingerprint_invalid".into(),
            ));
        }
        Ok(fingerprint)
    }

    pub fn open_probe(
        &self,
        scope: &SessionScope,
        slot: Slot,
    ) -> Result<NativeProbeSocket, ServiceError> {
        self.check_live(scope, slot)?;
        let view = self.view(slot).ok_or(ServiceError::InvalidRequest)?;
        NativeProbeSocket::open(view.routes.interface, view.source, view.probe.target_ipv4)
            .map_err(|_| ServiceError::Backend("member_probe_socket_failed".into()))
    }

    pub fn rebind(&mut self, scope: &SessionScope) -> Result<(), ServiceError> {
        self.check(scope)?;
        if self.closing {
            return Err(ServiceError::Backend("member_start_fenced".into()));
        }
        let mut first = None;
        for slot in [Slot::A, Slot::B] {
            if self.view(slot).is_some() {
                let result = self
                    .check_live(scope, slot)
                    .and_then(|_| self.backends[index(slot)].rebind_udp())
                    .and_then(|state| {
                        if state == ServiceTunnelState::Running {
                            Ok(())
                        } else {
                            Err(ServiceError::Backend("member_rebind_incomplete".into()))
                        }
                    });
                if let Err(e) = result {
                    first.get_or_insert(e);
                }
            }
        }
        first.map_or(Ok(()), Err)
    }

    fn check(&self, scope: &SessionScope) -> Result<(), ServiceError> {
        if &self.scope == scope {
            Ok(())
        } else {
            Err(ServiceError::UnauthorizedClient)
        }
    }
    pub fn check_live(&self, scope: &SessionScope, slot: Slot) -> Result<(), ServiceError> {
        self.check(scope)?;
        if self.closing {
            return Err(ServiceError::Backend("member_not_running".into()));
        }
        let view = self
            .view(slot)
            .ok_or_else(|| ServiceError::Backend("member_not_running".into()))?;
        if self.backends[index(slot)].member_interface_index()? != view.routes.interface {
            return Err(ServiceError::Backend("member_interface_changed".into()));
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
