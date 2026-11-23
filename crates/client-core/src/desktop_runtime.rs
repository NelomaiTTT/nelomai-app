//! Desktop orchestration under the existing Core writer gates. Native health
//! and failover live in the helper; neither requires these panel calls to run.
use super::*;
use nelomai_client_storage::{RuntimeAuthScope, StoredDesktopRedundancy};
use nelomai_client_tunnel::{
    redundancy::{protocol::Command, session::SessionPhase},
    DesktopTunnelOptions,
};
use nelomai_contracts::RedundancySession;

// The panel frees uncommitted leases after five minutes. Reconcile the exact
// reservation then, even if native health could never classify it as failed.
const CANDIDATE_LEASE_WINDOW: Duration = Duration::from_secs(300);

#[derive(Default)]
pub(super) struct CandidateWatchdog(Option<CandidateLeaseClock>);

#[derive(Clone)]
struct CandidateLeaseClock {
    operation_id: String,
    started: tokio::time::Instant,
    uptime_at_start: Option<Duration>,
}

impl CandidateLeaseClock {
    fn start(operation_id: &str) -> Self {
        Self {
            operation_id: operation_id.into(),
            started: tokio::time::Instant::now(),
            uptime_at_start: uptime_including_suspend(),
        }
    }

    fn expired(&self) -> bool {
        self.expired_at(uptime_including_suspend())
    }

    fn expired_at(&self, uptime: Option<Duration>) -> bool {
        self.started.elapsed() >= CANDIDATE_LEASE_WINDOW
            || self
                .uptime_at_start
                .zip(uptime)
                .is_some_and(|(start, now)| now.saturating_sub(start) >= CANDIDATE_LEASE_WINDOW)
    }
}

// The panel lease ages while the client sleeps. Use elapsed time that includes
// suspend so corrections to the system's wall clock cannot expire a reservation.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn uptime_including_suspend() -> Option<Duration> {
    #[cfg(target_os = "linux")]
    const CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;
    #[cfg(target_os = "macos")]
    const CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC_RAW;

    let mut sample = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(CLOCK, &mut sample) } != 0 {
        return None;
    }
    Some(Duration::new(
        sample.tv_sec.try_into().ok()?,
        sample.tv_nsec.try_into().ok()?,
    ))
}

#[cfg(windows)]
fn uptime_including_suspend() -> Option<Duration> {
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;

    Some(Duration::from_millis(unsafe { GetTickCount64() }))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn uptime_including_suspend() -> Option<Duration> {
    None
}

impl CandidateWatchdog {
    fn candidate_operation(pair: &StoredDesktopRedundancy) -> Option<&str> {
        let request = pair.pending_acquire.as_ref()?;
        let candidate = pair.candidate.as_ref()?;
        // Reuse of a CURRENT peer has no candidate lifetime on the panel.
        (request.replace_lease_id.as_deref() != Some(candidate.candidate_lease_id.as_str()))
            .then_some(request.operation_id.as_str())
    }

    fn candidate_clock(&self, pair: &StoredDesktopRedundancy) -> Option<&CandidateLeaseClock> {
        let operation = Self::candidate_operation(pair)?;
        self.0
            .as_ref()
            .filter(|clock| clock.operation_id == operation)
    }

    fn expired(&self, pair: &StoredDesktopRedundancy) -> bool {
        // After a runtime restart the journal survives but elapsed time does not.
        // Reconcile CURRENT membership before installing a reservation with an unknown age.
        Self::candidate_operation(pair).is_some()
            && self
                .candidate_clock(pair)
                .is_none_or(CandidateLeaseClock::expired)
    }
}

enum DesktopStopPreparation<'a> {
    Manual,
    Frozen(&'a nelomai_client_tunnel::redundancy::protocol::Snapshot),
    #[cfg(target_os = "macos")]
    VerifiedAbsent(&'a (dyn Fn() -> bool + Sync)),
}

impl<A: CoreApi, S: RuntimeStateStore, T: TunnelController, L: CoreLogger> ClientCore<A, S, T, L> {
    /// Probe only when selection is actually needed. Discovery happens outside
    /// the writer; tick revalidates ownership before accepting its results.
    pub async fn desktop_redundancy_probe_context(
        &self,
    ) -> Result<Option<(Layer, EgressMode)>, CoreError> {
        let _writer = self.connection_gate.lock().await;
        let stored = self.load_runtime()?;
        let Some(pair) = stored.desktop_redundancy.as_ref() else {
            return Ok(None);
        };
        if pair.stop.is_some()
            || stored.pending_compensation_stop.is_some()
            || !pair.primary_reported
            || !pair.session.standby_desired
            || pair.candidate.is_some()
        {
            return Ok(None);
        }
        let snapshot = self
            .tunnel
            .desktop_redundancy_command(Command::Status {
                scope: desktop_redundancy::scope(pair, stored.slot)?,
            })
            .await?;
        let mut observed = pair.clone();
        sync_helper_ack(&mut observed, stored.slot, &snapshot)?;
        let inactive = if snapshot.session.active == nelomai_client_tunnel::redundancy::Slot::A {
            1
        } else {
            0
        };
        let initial_attach =
            inactive == 1 && snapshot.current_leases[1].is_none() && pair.session.standby.is_some();
        Ok((snapshot.session.phase == SessionPhase::Running
            && !snapshot.cleanup_pending
            && snapshot.primary_ready
            && snapshot.session.role_confirmed
            && snapshot.leases[inactive].is_none()
            && !initial_attach)
            .then_some((pair.connection.layer, pair.connection.egress_mode)))
    }
    pub async fn desktop_redundancy_status(
        &self,
    ) -> Result<Option<nelomai_client_tunnel::redundancy::protocol::Snapshot>, CoreError> {
        let _writer = self.connection_gate.lock().await;
        let stored = self.load_runtime()?;
        let Some(pair) = stored.desktop_redundancy.as_ref() else {
            return Ok(None);
        };
        let snapshot = self
            .tunnel
            .desktop_redundancy_command(Command::Status {
                scope: desktop_redundancy::scope(pair, stored.slot)?,
            })
            .await?;
        // Display is not a generation write or permission to send a panel call.
        // A helper ACK may precede the protected metadata save; use the same
        // exact-scope receipt validation, without changing the record here.
        let mut observed = pair.clone();
        sync_helper_ack(&mut observed, stored.slot, &snapshot)?;
        Ok(Some(snapshot))
    }

    /// One bounded scheduling step. The application reuses its existing worker;
    /// native probes/failover keep running when the application is absent.
    /// Never hold a lifecycle writer while awaiting a panel response.
    pub async fn desktop_redundancy_tick(
        &self,
        probes: Vec<ProbeResult>,
    ) -> Result<Option<nelomai_client_tunnel::redundancy::protocol::Snapshot>, CoreError> {
        self.desktop_redundancy_tick_guarded(probes, None, || true)
            .await
    }

    pub async fn desktop_redundancy_tick_guarded(
        &self,
        probes: Vec<ProbeResult>,
        wake_stamp: Option<i64>,
        recovery_allowed: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<Option<nelomai_client_tunnel::redundancy::protocol::Snapshot>, CoreError> {
        let Ok(mut watchdog) = self.desktop_sync_gate.try_lock() else {
            return Ok(None);
        };
        let cancel_epoch = StartCancellationEpoch(self.start_cancel_epoch.load(Ordering::SeqCst));
        let allowed = self.desktop_dispatch_allowed(cancel_epoch, recovery_allowed);
        #[cfg(target_os = "macos")]
        let (wake_scope, allowed) = {
            let scope = crate::MacosStartWake::new(wake_stamp, allowed);
            let check = scope.allowed.clone();
            (scope, move || check())
        };
        let (auth_scope, mut pair) = {
            let _writer = self.connection_gate.lock().await;
            let stored = self.load_runtime()?;
            let Some(pair) = stored.desktop_redundancy else {
                return Ok(None);
            };
            if !allowed() || pair.stop.is_some() || stored.pending_compensation_stop.is_some() {
                return Ok(None);
            }
            (stored.auth_scope, pair)
        };
        // The auth owner may wait for a network refresh. Local Status and Stop
        // must be able to take the writer while authorization is in flight.
        let access = self.auth.access(None).await;
        let (stored, pair, snapshot, access) = {
            let _writer = self.connection_gate.lock().await;
            if !allowed() {
                return Ok(None);
            }
            let mut stored = self.load_runtime()?;
            if stored.auth_scope != auth_scope
                || stored.desktop_redundancy.as_ref() != Some(&pair)
                || stored.pending_compensation_stop.is_some()
            {
                return Ok(None);
            }
            let access = access?;
            if stored.auth_scope.as_ref()
                != Some(&RuntimeAuthScope {
                    auth_epoch: access.auth_epoch(),
                    family: access.family().into(),
                    identity: access.identity().clone(),
                })
            {
                return Err(CoreError::Storage);
            }
            let scope = desktop_redundancy::scope(&pair, stored.slot)?;
            let snapshot = self
                .tunnel
                .desktop_redundancy_command(Command::Status { scope })
                .await;
            if !allowed() {
                return Ok(None);
            }
            let snapshot = snapshot?;
            if sync_helper_ack(&mut pair, stored.slot, &snapshot)? {
                stored.desktop_redundancy = Some(pair.clone());
                self.store.save(&stored).map_err(|_| CoreError::Storage)?;
                if !allowed() {
                    return Ok(None);
                }
            }
            desktop_redundancy::validate_snapshot(&pair, stored.slot, &snapshot)?;
            if snapshot.session.phase != SessionPhase::Running
                || snapshot.cleanup_pending
                || snapshot.retirement_pending
            {
                return Ok(Some(snapshot));
            }
            let candidate_expired = watchdog.expired(&pair);
            if pair.primary_reported
                && snapshot.session.role_confirmed
                && snapshot.primary_ready
                && snapshot.session.active == nelomai_client_tunnel::redundancy::Slot::A
                && snapshot.current_leases[1].is_none()
                && snapshot.leases[1].is_none()
                && pair.session.standby.is_some()
                && pair.pending_acquire.is_none()
                && pair.candidate.is_none()
            {
                let command = desktop_redundancy::attach_command(&pair, stored.slot, &snapshot)?;
                return self
                    .send_desktop_member(command, cancel_epoch, wake_stamp, allowed, None)
                    .await;
            }
            if pair.primary_reported && snapshot.session.role_confirmed && snapshot.primary_ready {
                let inactive =
                    if snapshot.session.active == nelomai_client_tunnel::redundancy::Slot::A {
                        1
                    } else {
                        0
                    };
                if snapshot.standby_failed
                    && snapshot.session.committed[inactive]
                    && pair.pending_acquire.is_none()
                    && pair.candidate.is_none()
                {
                    let command = Command::RetireInactive {
                        scope: snapshot.session.scope.clone(),
                        slot: snapshot.session.active.other(),
                        lease_id: snapshot.leases[inactive]
                            .clone()
                            .ok_or(CoreError::Storage)?,
                        expected_revision: snapshot.session.local_revision,
                        expected_network_epoch: snapshot.session.network_epoch,
                        expected_membership_generation: snapshot.session.membership_generation,
                    };
                    return self
                        .dispatch_desktop_recovery_command(
                            command,
                            cancel_epoch,
                            wake_stamp,
                            allowed,
                            None,
                        )
                        .await;
                }
                if let Some(candidate) = pair.candidate.as_ref() {
                    if !candidate_expired && snapshot.leases[inactive].is_none() {
                        let command = desktop_redundancy::stage_command(
                            &pair,
                            stored.slot,
                            &snapshot,
                            candidate,
                        )?;
                        return self
                            .send_desktop_member(
                                command,
                                cancel_epoch,
                                wake_stamp,
                                allowed,
                                watchdog.candidate_clock(&pair),
                            )
                            .await;
                    }
                } else if snapshot.leases[inactive].is_none()
                    && pair.session.standby_desired
                    && pair.pending_acquire.is_none()
                {
                    let request = desktop_redundancy::acquire_request(
                        &pair,
                        stored.slot,
                        &snapshot,
                        &Uuid::new_v4().to_string(),
                        probes.clone(),
                    )?;
                    // Only the creator knows this operation was never sent before.
                    watchdog.0 = Some(CandidateLeaseClock::start(&request.operation_id));
                    pair.pending_acquire = Some(request);
                    stored.desktop_redundancy = Some(pair.clone());
                    self.store.save(&stored).map_err(|_| CoreError::Storage)?;
                }
                // Acquire's operation identity is stable, but its measurements
                // are not: the panel validates them only before allocation.
                // Existing-candidate replay is idempotent with fresh probes.
                if pair.candidate.is_none() {
                    if let Some(request) = pair.pending_acquire.as_mut() {
                        if request.probes != probes {
                            request.probes = probes;
                            stored.desktop_redundancy = Some(pair.clone());
                            self.store.save(&stored).map_err(|_| CoreError::Storage)?;
                        }
                    }
                }
            }
            (stored, pair, snapshot, access)
        };
        // The existing coordinator observes Start/role/network contexts. Refresh
        // outside the writer; the helper revalidates the exact snapshot at CAS.
        if let Ok(_split) = self.split_tunnel_gate.try_lock() {
            let mut policy = self
                .split_tunnel_store
                .load()
                .map_err(|_| CoreError::Storage)?;
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            if let Some(updated) = self
                .refresh_retained_split_tunnel(
                    &mut policy,
                    now,
                    crate::split_tunnel::resolve_domain_ipv4,
                    crate::split_tunnel::RetainedRefresh::Tick(&snapshot, cancel_epoch),
                    &allowed,
                    #[cfg(target_os = "macos")]
                    Some(&wake_scope),
                )
                .await?
            {
                self.split_tunnel_store
                    .save(&policy)
                    .map_err(|_| CoreError::Storage)?;
                return Ok(Some(updated));
            }
        }
        if !allowed() {
            return Ok(None);
        }
        let candidate_expired = watchdog.expired(&pair);
        if pair.candidate.is_some()
            && (candidate_expired || snapshot.standby_failed)
            && snapshot.primary_ready
            && snapshot.session.role_confirmed
        {
            // A commit response may have been lost. Reconcile BEFORE removing
            // a candidate, so a server-CURRENT member is never forgotten.
            let response = self
                .api
                .report_redundant_role(&access, &canonical_role_request(&snapshot)?)
                .await;
            let _writer = self.connection_gate.lock().await;
            let mut current = self.load_runtime()?;
            if !allowed()
                || current.auth_scope != stored.auth_scope
                || current.desktop_redundancy.as_ref() != Some(&pair)
                || current.pending_compensation_stop.is_some()
            {
                return Ok(None);
            }
            let fresh = self
                .tunnel
                .desktop_redundancy_command(Command::Status {
                    scope: snapshot.session.scope.clone(),
                })
                .await;
            if !allowed() {
                return Ok(None);
            }
            let fresh = fresh?;
            desktop_redundancy::validate_snapshot(&pair, current.slot, &fresh)?;
            let candidate = pair.candidate.as_ref().ok_or(CoreError::Storage)?;
            let i = if candidate.candidate_slot == RedundancyMemberSlot::A {
                0
            } else {
                1
            };
            let response = response?;
            if response.action != nelomai_contracts::RedundantRoleAction::Acknowledged
                || response.local_active_lease_id != canonical_role_request(&fresh)?.active_lease_id
                || !response.session.standby_desired
            {
                return Err(invalid_operation_reconcile_response());
            }
            let committed = if i == 0 {
                &response.session.slot_a_lease_id
            } else {
                &response.session.slot_b_lease_id
            };
            if committed.as_deref() == Some(candidate.candidate_lease_id.as_str()) {
                let command = desktop_redundancy::commit_command(
                    &pair,
                    current.slot,
                    &fresh,
                    &RedundantSessionResponse {
                        api_version: response.api_version,
                        request_id: response.request_id,
                        session: response.session,
                    },
                )?;
                let Some(receipt) = self
                    .dispatch_desktop_recovery_command(
                        command,
                        cancel_epoch,
                        wake_stamp,
                        allowed,
                        None,
                    )
                    .await?
                else {
                    return Ok(None);
                };
                let mut next = pair;
                sync_helper_ack(&mut next, current.slot, &receipt)?;
                current.desktop_redundancy = Some(next);
                self.store.save(&current).map_err(|_| CoreError::Storage)?;
                return Ok(Some(receipt));
            }
            desktop_redundancy::confirm_role_command(&fresh, &response)?;
            if !fresh.primary_ready || (!candidate_expired && !fresh.standby_failed) {
                return Ok(Some(fresh));
            }
            if fresh.leases[i].as_deref() == Some(candidate.candidate_lease_id.as_str()) {
                let command = Command::RemoveStandby {
                    scope: fresh.session.scope.clone(),
                    slot: fresh.session.active.other(),
                    lease_id: candidate.candidate_lease_id.clone(),
                    expected_revision: fresh.session.local_revision,
                    expected_network_epoch: fresh.session.network_epoch,
                    expected_membership_generation: fresh.session.membership_generation,
                };
                let Some(removed) = self
                    .dispatch_desktop_recovery_command(
                        command,
                        cancel_epoch,
                        wake_stamp,
                        allowed,
                        None,
                    )
                    .await?
                else {
                    return Ok(None);
                };
                desktop_redundancy::validate_snapshot(&pair, current.slot, &removed)?;
            } else if fresh.leases[i].is_some() {
                return Err(invalid_operation_reconcile_response());
            }
            current
                .desktop_redundancy
                .as_mut()
                .ok_or(CoreError::Storage)?
                .candidate = None;
            self.store.save(&current).map_err(|_| CoreError::Storage)?;
            if candidate_expired {
                self.logger.record(CoreLogEvent {
                    kind: "desktop.redundancy.candidate_expired",
                    operation_id: pair
                        .pending_acquire
                        .as_ref()
                        .map(|p| p.operation_id.clone()),
                    request_id: Some(candidate.request_id.clone()),
                    code: Some(if fresh.leases[i].is_none() {
                        "stage_unconfirmed".into()
                    } else if fresh.standby_ready {
                        "lease_window_elapsed".into()
                    } else {
                        "readiness_unconfirmed".into()
                    }),
                });
            }
            // Existing scheduling backoff prevents a broken member restart loop.
            return Err(CoreApiError::Retryable.into());
        }
        if !pair.primary_reported && snapshot.primary_ready {
            let request = RedundantRoleRequest {
                session_id: pair.session.session_id.clone(),
                active_lease_id: pair.connection.lease_id.clone(),
                expected_role_generation: pair.session.role_generation,
                expected_membership_generation: pair.session.membership_generation,
                reason: Some("primary_ready".into()),
                observed_at: None,
            };
            let started = Instant::now();
            self.logger.record(CoreLogEvent {
                kind: "desktop.redundancy.primary_report_started",
                operation_id: Some(pair.session.session_id.clone()),
                request_id: None,
                code: None,
            });
            let response = self.api.report_redundant_role(&access, &request).await;
            if !allowed() {
                return Ok(None);
            }
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    self.logger.record_timed(
                        CoreLogEvent {
                            kind: "desktop.redundancy.primary_report_failed",
                            operation_id: Some(pair.session.session_id.clone()),
                            request_id: None,
                            code: Some(
                                match &error {
                                    CoreApiError::Unauthorized => "signed_out",
                                    CoreApiError::AccessExpired => "access_expired",
                                    CoreApiError::Retryable => "temporary_network_error",
                                    CoreApiError::Rejected { .. } => "server_rejected",
                                }
                                .into(),
                            ),
                        },
                        elapsed_millis(started),
                    );
                    // Retry on the next coordinator tick, revalidating its guards.
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    if error == CoreApiError::Retryable {
                        return Ok(None);
                    }
                    return Err(error.into());
                }
            };
            // Initial B can already be CURRENT in the panel without being
            // locally installed yet. Validate against protected issuance, not
            // the native installed map used for subsequent role transitions.
            let view = &response.session;
            if response.action != nelomai_contracts::RedundantRoleAction::Acknowledged
                || response.local_active_lease_id != pair.connection.lease_id
                || view.session_id != pair.session.session_id
                || view.active_lease_id.as_deref() != Some(pair.connection.lease_id.as_str())
                || view.slot_a_lease_id.as_deref() != Some(pair.connection.lease_id.as_str())
                || view.slot_b_lease_id.as_deref()
                    != pair
                        .session
                        .standby
                        .as_ref()
                        .map(|m| m.connection.lease_id.as_str())
                || view.role_generation != pair.session.role_generation
                || view.membership_generation != pair.session.membership_generation
                || !matches!(
                    view.state,
                    nelomai_contracts::RedundantSessionState::Connected
                        | nelomai_contracts::RedundantSessionState::Degraded
                )
            {
                return Err(invalid_operation_reconcile_response());
            }
            let _writer = self.connection_gate.lock().await;
            let mut current = self.load_runtime()?;
            // A Stop/auth transition/new Start wins over this delayed reply.
            if !allowed()
                || current.auth_scope != stored.auth_scope
                || current.desktop_redundancy.as_ref() != Some(&pair)
                || current.pending_compensation_stop.is_some()
            {
                return Ok(None);
            }
            current
                .desktop_redundancy
                .as_mut()
                .ok_or(CoreError::Storage)?
                .primary_reported = true;
            self.store.save(&current).map_err(|_| CoreError::Storage)?;
            self.logger.record_timed(
                CoreLogEvent {
                    kind: "desktop.redundancy.primary_report_confirmed",
                    operation_id: Some(pair.session.session_id.clone()),
                    request_id: Some(response.request_id.clone()),
                    code: None,
                },
                elapsed_millis(started),
            );
        } else if !snapshot.session.role_confirmed {
            let request = desktop_redundancy::role_request(&snapshot)?;
            // Native promotion can change the external route while preserving
            // the VIP. Pooled connections still belong to the previous route.
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            self.api.reset_transport()?;
            let started = Instant::now();
            self.logger.record(CoreLogEvent {
                kind: "desktop.redundancy.role_report_started",
                operation_id: Some(pair.session.session_id.clone()),
                request_id: None,
                code: None,
            });
            let response = self.api.report_redundant_role(&access, &request).await;
            if !allowed() {
                return Ok(None);
            }
            let response = match response {
                Ok(response) => {
                    self.logger.record_timed(
                        CoreLogEvent {
                            kind: "desktop.redundancy.role_report_succeeded",
                            operation_id: Some(pair.session.session_id.clone()),
                            request_id: Some(response.request_id.clone()),
                            code: None,
                        },
                        elapsed_millis(started),
                    );
                    response
                }
                Err(error) => {
                    self.logger.record_timed(
                        CoreLogEvent {
                            kind: "desktop.redundancy.role_report_failed",
                            operation_id: Some(pair.session.session_id.clone()),
                            request_id: None,
                            code: Some(match &error {
                                CoreApiError::Unauthorized => "signed_out".into(),
                                CoreApiError::AccessExpired => "access_expired".into(),
                                CoreApiError::Retryable => "temporary_network_error".into(),
                                CoreApiError::Rejected { code, .. } => code.clone(),
                            }),
                        },
                        elapsed_millis(started),
                    );
                    return Err(error.into());
                }
            };
            let _writer = self.connection_gate.lock().await;
            let mut current = self.load_runtime()?;
            if !allowed()
                || current.auth_scope != stored.auth_scope
                || current.desktop_redundancy.as_ref() != Some(&pair)
                || current.pending_compensation_stop.is_some()
            {
                return Ok(None);
            }
            let fresh = self
                .tunnel
                .desktop_redundancy_command(Command::Status {
                    scope: snapshot.session.scope.clone(),
                })
                .await;
            if !allowed() {
                return Ok(None);
            }
            let fresh = fresh?;
            desktop_redundancy::validate_snapshot(&pair, current.slot, &fresh)?;
            let command = desktop_redundancy::confirm_role_command(&fresh, &response)?;
            let Some(confirmed) = self
                .dispatch_desktop_recovery_command(command, cancel_epoch, wake_stamp, allowed, None)
                .await?
            else {
                return Ok(None);
            };
            let mut next = pair.clone();
            next.session.role_generation = response.session.role_generation;
            desktop_redundancy::validate_snapshot(&next, current.slot, &confirmed)?;
            current.desktop_redundancy = Some(next);
            self.store.save(&current).map_err(|_| CoreError::Storage)?;
            self.logger.record_timed(
                CoreLogEvent {
                    kind: "desktop.redundancy.role_confirmed",
                    operation_id: Some(pair.session.session_id.clone()),
                    request_id: Some(response.request_id.clone()),
                    code: None,
                },
                elapsed_millis(started),
            );
            return Ok(Some(confirmed));
        } else if pair.primary_reported && snapshot.primary_ready && pair.candidate.is_none() {
            if let Some(request) = pair.pending_acquire.as_ref() {
                let attempt = CandidateLeaseClock::start(&request.operation_id);
                let response = self.api.acquire_redundant_standby(&access, request).await;
                // A fresh allocation starts at this dispatch. A replay keeps the
                // earlier bound even if the original request lost its reply in sleep.
                if response.as_ref().is_ok_and(|candidate| !candidate.reused) {
                    watchdog.0 = Some(attempt);
                }
                if !allowed() {
                    return Ok(None);
                }
                let response = match response {
                    Ok(response) => response,
                    Err(CoreApiError::Rejected { ref code, .. })
                        if code == "operation_id_conflict" =>
                    {
                        // The server's candidate TTL consumed this ID. Only a
                        // canonical unchanged CURRENT map permits a fresh ID.
                        let response = self
                            .api
                            .report_redundant_role(&access, &canonical_role_request(&snapshot)?)
                            .await;
                        let _writer = self.connection_gate.lock().await;
                        let mut current = self.load_runtime()?;
                        if !allowed()
                            || current.auth_scope != stored.auth_scope
                            || current.desktop_redundancy.as_ref() != Some(&pair)
                            || current.pending_compensation_stop.is_some()
                        {
                            return Ok(None);
                        }
                        let fresh = self
                            .tunnel
                            .desktop_redundancy_command(Command::Status {
                                scope: snapshot.session.scope.clone(),
                            })
                            .await;
                        if !allowed() {
                            return Ok(None);
                        }
                        let fresh = fresh?;
                        desktop_redundancy::validate_snapshot(&pair, current.slot, &fresh)?;
                        let response = response?;
                        if response.action != nelomai_contracts::RedundantRoleAction::Acknowledged
                            || !response.session.standby_desired
                        {
                            return Err(invalid_operation_reconcile_response());
                        }
                        desktop_redundancy::confirm_role_command(&fresh, &response)?;
                        current
                            .desktop_redundancy
                            .as_mut()
                            .ok_or(CoreError::Storage)?
                            .pending_acquire = None;
                        self.store.save(&current).map_err(|_| CoreError::Storage)?;
                        return Err(CoreApiError::Retryable.into());
                    }
                    Err(error) => return Err(error.into()),
                };
                let _writer = self.connection_gate.lock().await;
                let mut current = self.load_runtime()?;
                if !allowed()
                    || current.auth_scope != stored.auth_scope
                    || current.desktop_redundancy.as_ref() != Some(&pair)
                    || current.pending_compensation_stop.is_some()
                {
                    return Ok(None);
                }
                let fresh = self
                    .tunnel
                    .desktop_redundancy_command(Command::Status {
                        scope: snapshot.session.scope.clone(),
                    })
                    .await;
                if !allowed() {
                    return Ok(None);
                }
                let fresh = fresh?;
                let mut next = pair.clone();
                next.candidate = Some(response.clone());
                // Validate before persistence; native Stage requires a protected candidate.
                let _command =
                    desktop_redundancy::stage_command(&next, current.slot, &fresh, &response)?;
                // The expiry sweep can lag the lease window. Keep replaying the
                // known operation until the panel confirms that its ID was used.
                if watchdog.expired(&next) {
                    return Err(CoreApiError::Retryable.into());
                }
                current.desktop_redundancy = Some(next.clone());
                self.store.save(&current).map_err(|_| CoreError::Storage)?;
                #[cfg(target_os = "linux")]
                if fresh.primary_ready {
                    return self
                        .send_desktop_member(
                            _command,
                            cancel_epoch,
                            wake_stamp,
                            allowed,
                            watchdog.candidate_clock(&next),
                        )
                        .await;
                }
            }
        } else if pair.primary_reported && pair.candidate.is_some() && snapshot.standby_ready {
            let request = desktop_redundancy::commit_request(&pair, stored.slot, &snapshot)?;
            if watchdog.expired(&pair) || !allowed() {
                return Ok(None);
            }
            let response = self.api.commit_redundant_candidate(&access, &request).await;
            if !allowed() {
                return Ok(None);
            }
            let response = match response {
                Ok(response) => response,
                Err(CoreApiError::Rejected { ref code, .. })
                    if code == "session_membership_conflict" =>
                {
                    // A successful commit with lost response is not blindly
                    // repeated at a guessed generation. Ask for the canonical
                    // same-active view, then validate the exact candidate below.
                    let observed = self
                        .api
                        .report_redundant_role(
                            &access,
                            &RedundantRoleRequest {
                                session_id: request.session_id.clone(),
                                active_lease_id: request.expected_active_lease_id.clone(),
                                expected_role_generation: request.expected_role_generation,
                                expected_membership_generation: request
                                    .expected_membership_generation,
                                reason: None,
                                observed_at: None,
                            },
                        )
                        .await;
                    if !allowed() {
                        return Ok(None);
                    }
                    let observed = observed?;
                    if observed.action != nelomai_contracts::RedundantRoleAction::Acknowledged
                        || observed.local_active_lease_id != request.expected_active_lease_id
                    {
                        return Err(invalid_operation_reconcile_response());
                    }
                    RedundantSessionResponse {
                        api_version: observed.api_version,
                        request_id: observed.request_id,
                        session: observed.session,
                    }
                }
                Err(error) => return Err(error.into()),
            };
            let _writer = self.connection_gate.lock().await;
            let mut current = self.load_runtime()?;
            if !allowed()
                || current.auth_scope != stored.auth_scope
                || current.desktop_redundancy.as_ref() != Some(&pair)
                || current.pending_compensation_stop.is_some()
            {
                return Ok(None);
            }
            let fresh = self
                .tunnel
                .desktop_redundancy_command(Command::Status {
                    scope: snapshot.session.scope.clone(),
                })
                .await;
            if !allowed() {
                return Ok(None);
            }
            let fresh = fresh?;
            let command =
                desktop_redundancy::commit_command(&pair, current.slot, &fresh, &response)?;
            let Some(committed) = self
                .dispatch_desktop_recovery_command(command, cancel_epoch, wake_stamp, allowed, None)
                .await?
            else {
                return Ok(None);
            };
            let mut next = pair.clone();
            sync_helper_ack(&mut next, current.slot, &committed)?;
            current.desktop_redundancy = Some(next);
            self.store.save(&current).map_err(|_| CoreError::Storage)?;
            return Ok(Some(committed));
        }
        Ok(Some(snapshot))
    }

    /// Called with the existing intent/split/connection writer gates. Freeze
    /// before persisting the last-active identity, then close without awaiting
    /// the panel. The existing ten-second cleanup worker owns later retries.
    pub async fn prepare_desktop_recovery(
        &self,
        observed: &nelomai_client_tunnel::redundancy::protocol::Snapshot,
    ) -> Result<bool, CoreError> {
        Ok(self
            .prepare_desktop_recovery_guarded(observed, None, || true)
            .await?
            .unwrap_or(false))
    }

    /// None means the platform deferred a new Freeze before any native change.
    pub async fn prepare_desktop_recovery_guarded(
        &self,
        observed: &nelomai_client_tunnel::redundancy::protocol::Snapshot,
        wake_stamp: Option<i64>,
        recovery_allowed: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<Option<bool>, CoreError> {
        let cancel_epoch = StartCancellationEpoch(self.start_cancel_epoch.load(Ordering::SeqCst));
        let allowed = self.desktop_dispatch_allowed(cancel_epoch, recovery_allowed);
        if !observed.stalled
            || observed.primary_ready
            || !matches!(
                observed.session.phase,
                SessionPhase::Running | SessionPhase::Stopping | SessionPhase::Stopped
            )
        {
            return Ok(Some(false));
        }
        // No global cancellation from a stale background observation. Both the
        // protected owner and the helper's atomic health/revision fence must match.
        let _intent = self.intent_recovery_gate.lock().await;
        let _split = self.split_tunnel_gate.lock().await;
        let _writer = self.connection_gate.lock().await;
        let stored = self.load_runtime()?;
        let Some(pair) = stored.desktop_redundancy.as_ref() else {
            return Ok(Some(false));
        };
        desktop_redundancy::validate_snapshot(pair, stored.slot, observed)?;
        if pair.stop.is_some() || stored.pending_compensation_stop.is_some() {
            // An exact accepted cold request can outlive its first caller.
            // A retaining/manual request or unrelated compensation must not
            // become automatic-recovery authority through this retry.
            return Ok(Some(
                pair.stop
                    .as_ref()
                    .zip(stored.pending_compensation_stop.as_ref())
                    .is_some_and(|(stop, pending)| {
                        !stop.retain_active_peer
                            && !pending.accept_warm
                            && stop.operation_id == pending.operation_id
                            && stop.active_lease_id == pending.lease_id
                            && pending.recovery_contract_version == Some(2)
                            && pending.redundant_session_id.as_deref()
                                == Some(pair.session.session_id.as_str())
                    }),
            ));
        }
        if !allowed() {
            return Ok(None);
        }
        // A previous freeze may have closed native traffic before a protected
        // journal write failed. Retry the same helper-fenced cold cleanup; a
        // stopped snapshot alone never authorizes a new Start or WARM retention.
        let command = Command::PrepareRecoveryStop {
            scope: observed.session.scope.clone(),
            expected_revision: observed.session.local_revision,
            expected_network_epoch: observed.session.network_epoch,
        };
        let Some(frozen) = self
            .dispatch_desktop_recovery_command(command, cancel_epoch, wake_stamp, allowed, None)
            .await?
        else {
            return Ok(None);
        };
        self.stop_desktop_with_frozen(stored, DesktopStopPreparation::Frozen(&frozen), false)
            .await?;
        Ok(Some(true))
    }

    pub(super) async fn stop_desktop_locally(
        &self,
        stored: nelomai_client_storage::RuntimeStateV1,
    ) -> Result<Connection, CoreError> {
        if let Some(pair) = stored.desktop_redundancy.as_ref() {
            if let Some(pending) = stored
                .pending_compensation_stop
                .as_ref()
                .filter(|_| pair.stop.is_none())
            {
                // Failed Start already sealed a cold cleanup identity. Manual
                // retry must not replace it with a new, retaining Stop intent.
                if pending.recovery_contract_version != Some(2)
                    || pending.redundant_session_id.as_deref()
                        != Some(pair.session.session_id.as_str())
                    || pending.lease_id != pair.connection.lease_id
                {
                    return Err(CoreError::Storage);
                }
                self.set_phase(Phase::Stopping).await;
                *self.active_recovery_episode.lock().await = None;
                self.close_desktop_pair(desktop_redundancy::scope(pair, stored.slot)?)
                    .await?;
                self.state.lock().await.connection = Some(pair.connection.clone());
                return Ok(pair.connection.clone());
            }
        }
        self.stop_desktop_with_frozen(stored, DesktopStopPreparation::Manual, true)
            .await
    }

    #[cfg(target_os = "macos")]
    pub(super) async fn stop_inferred_desktop_pair(
        &self,
        stored: nelomai_client_storage::RuntimeStateV1,
        epoch: StartCancellationEpoch,
        wake_stamp: Option<i64>,
        recovery_allowed: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Connection, CoreError> {
        let pair = stored
            .desktop_redundancy
            .as_ref()
            .ok_or(CoreError::Storage)?;
        let scope = desktop_redundancy::scope(pair, stored.slot)?;
        let allowed = Arc::new(self.desktop_dispatch_allowed(epoch, move || recovery_allowed()));
        let dispatch_allowed = allowed.clone();
        let prepared = self
            .dispatch_desktop_recovery_command(
                Command::PrepareStop { scope },
                epoch,
                wake_stamp,
                move || dispatch_allowed(),
                None,
            )
            .await;
        let error = match prepared {
            Ok(Some(frozen)) => {
                // Native accepted the scope. Finish even if admission has since expired.
                return self
                    .stop_desktop_with_frozen(stored, DesktopStopPreparation::Frozen(&frozen), true)
                    .await;
            }
            Ok(None) => return Err(CoreError::RecoveryDeferred),
            Err(error) => error,
        };
        if !allowed() {
            return Err(CoreError::RecoveryDeferred);
        }
        let absent = self.tunnel.desktop_redundancy_absent().await?;
        if !allowed() {
            return Err(CoreError::RecoveryDeferred);
        }
        if !absent {
            return Err(error);
        }
        self.stop_desktop_with_frozen(
            stored,
            DesktopStopPreparation::VerifiedAbsent(&*allowed),
            true,
        )
        .await
    }

    async fn stop_desktop_with_frozen(
        &self,
        mut stored: nelomai_client_storage::RuntimeStateV1,
        preparation: DesktopStopPreparation<'_>,
        ordinary: bool,
    ) -> Result<Connection, CoreError> {
        #[cfg(target_os = "macos")]
        let inferred_absent = matches!(&preparation, DesktopStopPreparation::VerifiedAbsent(_));
        #[cfg(not(target_os = "macos"))]
        let inferred_absent = false;
        let mut pair = stored
            .desktop_redundancy
            .clone()
            .ok_or(CoreError::Storage)?;
        let scope = desktop_redundancy::scope(&pair, stored.slot)?;
        self.set_phase(Phase::Stopping).await;
        {
            let mut episode = self.active_recovery_episode.lock().await;
            #[cfg(target_os = "macos")]
            if let DesktopStopPreparation::VerifiedAbsent(allowed) = &preparation {
                // Absence is evidence, not a previously accepted Stop. Recheck after
                // the asynchronous state locks, immediately before sealing the intent.
                if !allowed() {
                    return Err(CoreError::RecoveryDeferred);
                }
            }
            *episode = None;
        }
        let inferred = ordinary && !matches!(preparation, DesktopStopPreparation::Manual);
        let record = async {
            let stop = if let Some(stop) = pair.stop.clone() {
                stop
            } else {
                // A compensation request already sent must not change its lease
                // or retention payload into an ordinary warm Stop on retry.
                if stored.pending_compensation_stop.is_some() {
                    return Err(CoreError::Storage);
                }
                let native_receipt;
                let prepared = match &preparation {
                    DesktopStopPreparation::Frozen(frozen) => Some(*frozen),
                    #[cfg(target_os = "macos")]
                    DesktopStopPreparation::VerifiedAbsent(_) => None,
                    DesktopStopPreparation::Manual => {
                        match self
                            .tunnel
                            .desktop_redundancy_command(Command::PrepareStop {
                                scope: scope.clone(),
                            })
                            .await
                        {
                            Ok(receipt) => {
                                native_receipt = receipt;
                                Some(&native_receipt)
                            }
                            Err(error) => {
                                if !self.tunnel.desktop_redundancy_absent().await? {
                                    return Err(error.into());
                                }
                                None
                            }
                        }
                    }
                };
                match prepared {
                    Some(frozen) => {
                        sync_helper_ack(&mut pair, stored.slot, frozen)?;
                        stored.desktop_redundancy = Some(pair.clone());
                        desktop_redundancy::stop_record(
                            &pair,
                            stored.slot,
                            frozen,
                            &Uuid::new_v4().to_string(),
                            ordinary && frozen.session.phase == SessionPhase::Stopping,
                        )?
                    }
                    None => {
                        // Restart cleanup has no frozen last-active proof. Full
                        // server Stop accepts a historical member of this exact
                        // session; never infer a WARM role from protected metadata.
                        nelomai_client_storage::StoredDesktopRedundantStop {
                            background_cleanup: cfg!(any(target_os = "linux", target_os = "macos"))
                                && pair.primary_reported
                                && pair.session.async_stop_v1,
                            operation_id: Uuid::new_v4().to_string(),
                            active_lease_id: pair.connection.lease_id.clone(),
                            role_generation: pair.session.role_generation,
                            membership_generation: pair.session.membership_generation,
                            committed_leases: [
                                Some(pair.connection.lease_id.clone()),
                                pair.session
                                    .standby
                                    .as_ref()
                                    .map(|m| m.connection.lease_id.clone()),
                            ],
                            retain_active_peer: false,
                            role_confirmed: false,
                        }
                    }
                }
            };
            Ok::<_, CoreError>(stop)
        }
        .await;
        // A failed scope or generation check cannot authorize a passive close.
        let record = if inferred { Ok(record?) } else { record };
        let journal = async {
            let stop = record?;
            let current = std::iter::once(&pair.connection)
                .chain(
                    pair.session
                        .standby
                        .as_ref()
                        .map(|member| &member.connection),
                )
                .chain(
                    pair.candidate
                        .as_ref()
                        .map(|candidate| &candidate.connection),
                )
                .find(|connection| connection.lease_id == stop.active_lease_id)
                .cloned()
                .ok_or(CoreError::Storage)?;
            let pending = StoredPendingCompensationStop {
                inferred_release: inferred_absent,
                operation_id: stop.operation_id.clone(),
                lease_id: stop.active_lease_id.clone(),
                recovery_contract_version: Some(2),
                redundant_session_id: Some(pair.session.session_id.clone()),
                accept_warm: stop.retain_active_peer,
                failure_code: None,
            };
            if stored
                .pending_compensation_stop
                .as_ref()
                .is_some_and(|old| old != &pending)
            {
                return Err(CoreError::Storage);
            }
            stored
                .desktop_redundancy
                .as_mut()
                .ok_or(CoreError::Storage)?
                .stop = Some(stop.clone());
            stored.pending_compensation_stop = Some(pending);
            if self.store.save(&stored).is_err()
                && self.store.load().ok().flatten().as_ref() != Some(&stored)
            {
                return Err(CoreError::Storage);
            }
            // Lost write ACK is not lost intent. The worker can already see
            // this exact immutable request; do not strand recovery waiting for
            // a helper snapshot that the worker may finish and retire first.
            self.state.lock().await.connection = Some(current.clone());
            Ok::<_, CoreError>((current, stop))
        }
        .await;
        #[cfg(target_os = "macos")]
        if let DesktopStopPreparation::VerifiedAbsent(allowed) = &preparation {
            // Absence is not a native Stop receipt. Keep this journal gated,
            // and let replay recheck absence before any panel request.
            let (current, _) = journal?;
            if !allowed() {
                return Err(CoreError::RecoveryDeferred);
            }
            return Ok(current);
        }
        // Local Stop must neither wait for credentials/network nor cancel a
        // pending access request: the private auth channel fails closed when
        // such a request is dropped. The durable intent above is replayed by
        // the existing stop worker, including any required role reconciliation.
        let close_result = self.close_desktop_pair(scope).await;
        if !ordinary {
            if journal.is_err() {
                // No durable cleanup was accepted: the intent retains this
                // frozen scope and retries it. Phase::Stopping alone would let
                // the ordinary worker clear ownership before that retry.
                self.set_phase(Phase::Error).await;
            }
            // A durable cold request is acceptance, not native completion.
            // The existing worker retries close; reconciliation still prevents
            // a replacement Start until both native and server cleanup finish.
            if close_result.is_err() {
                return journal.map(|(connection, _)| connection);
            }
        } else {
            close_result?;
        }
        self.physical_network_change.lock().await.reset();
        self.clear_applied_physical_network_fingerprint();
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Operation)
            .await;
        self.clear_split_tunnel_warning(SplitTunnelWarningKind::Runtime)
            .await;
        journal.map(|(connection, _)| connection)
    }

    pub(super) async fn desktop_stop_retention(
        &self,
        access: &AccessSnapshot,
        pending: &StoredPendingCompensationStop,
    ) -> Result<bool, CoreError> {
        let stored = self.load_runtime()?;
        let Some(pair) = stored.desktop_redundancy else {
            return Ok(false);
        };
        if pending.redundant_session_id.as_deref() != Some(pair.session.session_id.as_str()) {
            return Err(CoreError::Storage);
        }
        let Some(stop) = pair.stop.as_ref() else {
            return Ok(false);
        }; // Failed Start: full compensation.
        if stop.operation_id != pending.operation_id
            || stop.active_lease_id != pending.lease_id
            || stop.retain_active_peer != pending.accept_warm
        {
            return Err(CoreError::Storage);
        }
        if !stop.retain_active_peer {
            return Ok(false);
        }
        if !stop.role_confirmed {
            let request = desktop_redundancy::stopped_role_request(&pair, stop)?;
            let response = self.api.report_redundant_role(access, &request).await?;
            let rebase = response.action == nelomai_contracts::RedundantRoleAction::Rebase;
            let generation = if rebase {
                desktop_redundancy::stopped_role_rebase(&pair, stop, &response)?
            } else {
                desktop_redundancy::validate_stopped_role_response(&pair, stop, &response)?
            };
            let mut current = self.load_runtime()?;
            if current.auth_scope != stored.auth_scope
                || current.pending_compensation_stop.as_ref() != Some(pending)
                || current.desktop_redundancy.as_ref() != Some(&pair)
            {
                return Err(CoreError::Storage);
            }
            let pair = current
                .desktop_redundancy
                .as_mut()
                .ok_or(CoreError::Storage)?;
            let frozen = pair.stop.as_mut().ok_or(CoreError::Storage)?;
            frozen.role_generation = generation;
            frozen.role_confirmed = !rebase;
            pair.session.role_generation = generation;
            self.store.save(&current).map_err(|_| CoreError::Storage)?;
            // Existing cleanup worker retries with the newly observed fence.
            // Never send retaining Stop merely because a rebase was persisted.
            if rebase {
                return Err(CoreApiError::Retryable.into());
            }
        }
        Ok(stop.retain_active_peer)
    }

    pub(super) async fn start_local_desktop(
        &self,
        mut request: TunnelStartRequest,
        connection: &Connection,
        server_session: Option<&RedundancySession>,
        start: (&str, StartCancellationEpoch),
        required: bool,
        admission: &dyn StartAdmission,
    ) -> Result<(), CoreError> {
        let allowed = || admission.allows_start();
        let (operation_id, epoch) = start;
        if !allowed() {
            return Err(CoreError::RecoveryDeferred);
        }
        #[cfg(target_os = "macos")]
        let native_guard = admission.macos_wake().map(|wake| {
            let allowed = wake.allowed.clone();
            self.desktop_wake_guard(
                epoch,
                wake.stamp,
                self.desktop_dispatch_allowed(epoch, move || allowed()),
            )
        });
        // Android and old/single helpers retain their original path. The desktop
        // reserve admission checks capability BEFORE obtaining a server lease.
        if !required {
            let mut stored = self.load_runtime()?;
            let pending = stored
                .pending_start
                .as_mut()
                .filter(|pending| pending.operation_id == operation_id)
                .ok_or(CoreError::Storage)?;
            self.ensure_start_not_cancelled(epoch)?;
            if !allowed() {
                return Err(CoreError::RecoveryDeferred);
            }
            // Record the native boundary before dispatch. A later failure
            // to write the compensation journal must not make this replay
            // indistinguishable from a Start deferred before dispatch.
            let previous_attempt = pending.native_start_attempted;
            pending.native_start_attempted = Some(true);
            self.store.save(&stored).map_err(|_| CoreError::Storage)?;
            if allowed() {
                self.ensure_start_not_cancelled(epoch)?;
                #[cfg(target_os = "macos")]
                let dispatched = match native_guard {
                    Some(guard) => self.tunnel.start_guarded(request, guard).await,
                    None => return self.tunnel.start(request).await.map_err(Into::into),
                };
                #[cfg(target_os = "macos")]
                if !matches!(&dispatched, Err(TunnelError::Backend(code)) if code == nelomai_client_tunnel::WAKE_DISPATCH_DEFERRED)
                {
                    return dispatched.map_err(Into::into);
                }
                #[cfg(not(target_os = "macos"))]
                return self.tunnel.start(request).await.map_err(Into::into);
            }
            // A refused write cannot have installed this Start. Restore the
            // preceding marker, including an unknown result from an older attempt.
            let pending = stored.pending_start.as_mut().ok_or(CoreError::Storage)?;
            pending.native_start_attempted = previous_attempt;
            self.store.save(&stored).map_err(|_| CoreError::Storage)?;
            return Err(CoreError::RecoveryDeferred);
        }
        if request.redundancy.is_none() || !self.tunnel.desktop_redundancy_supported().await? {
            return Err(CoreError::Tunnel("desktop_redundancy_unsupported".into()));
        }
        let start = request.redundancy.take().ok_or(CoreError::Storage)?;
        if start.state == RedundancyState::Disabled {
            return Err(CoreError::Tunnel("desktop_redundancy_unavailable".into()));
        }
        self.ensure_start_not_cancelled(epoch)?;
        let access = self.access_snapshot().await?;
        let auth_scope = RuntimeAuthScope {
            auth_epoch: access.auth_epoch(),
            family: access.family().into(),
            identity: access.identity().clone(),
        };
        let runtime = access.identity().slot;
        let primary_probe = start.primary.health_probe.ok_or(CoreError::Storage)?;
        let session = server_session
            .filter(|s| s.session_id == start.session_id)
            .ok_or(CoreError::Storage)?
            .clone();
        let pair = StoredDesktopRedundancy {
            primary_reported: false,
            runtime_generation: access
                .identity()
                .session_generation
                .ok_or(CoreError::Storage)?,
            connection_generation: epoch.0.checked_add(1).ok_or(CoreError::Storage)?,
            start_operation_id: start.operation_id,
            request_fingerprint: start.request_fingerprint,
            connection: connection.clone(),
            session,
            pending_acquire: None,
            candidate: None,
            stop: None,
        };
        let scope = desktop_redundancy::scope(&pair, runtime)?;
        let command = desktop_redundancy::primary_command(
            &pair,
            runtime,
            request.configuration,
            DesktopTunnelOptions::from_tunnel_options(&request.options),
            primary_probe,
        )?;
        let pinned = self
            .await_with_start_cancellation(
                Some(epoch),
                super::desktop_endpoint::pin_command(command),
            )
            .await?;
        if !allowed() {
            return Err(CoreError::RecoveryDeferred);
        }
        let mut stored = self.load_runtime()?;
        if stored.auth_scope.as_ref() != Some(&auth_scope) || stored.desktop_redundancy.is_some() {
            return Err(CoreError::Storage);
        }
        stored.desktop_redundancy = Some(pair.clone());
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        let dispatched = if allowed() {
            self.ensure_start_not_cancelled(epoch)?;
            #[cfg(target_os = "macos")]
            let result = match native_guard {
                Some(guard) => match self
                    .tunnel
                    .desktop_redundancy_command_guarded(pinned?, guard)
                    .await
                {
                    Err(TunnelError::Backend(code))
                        if code == nelomai_client_tunnel::WAKE_DISPATCH_DEFERRED =>
                    {
                        None
                    }
                    result => Some(result?),
                },
                None => Some(self.tunnel.desktop_redundancy_command(pinned?).await?),
            };
            #[cfg(not(target_os = "macos"))]
            let result = Some(self.tunnel.desktop_redundancy_command(pinned?).await?);
            result
        } else {
            None
        };
        let Some(mut snapshot) = dispatched else {
            stored.desktop_redundancy = None;
            self.store.save(&stored).map_err(|_| CoreError::Storage)?;
            return Err(CoreError::RecoveryDeferred);
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            self.ensure_start_not_cancelled(epoch)?;
            desktop_redundancy::validate_snapshot(&pair, stored.slot, &snapshot)?;
            if snapshot.session.phase != SessionPhase::Running || snapshot.cleanup_pending {
                return Err(CoreError::Tunnel("redundancy_primary_stopped".into()));
            }
            if snapshot.primary_ready {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                self.api.reset_transport()?;
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(CoreError::Tunnel("tunnel_start_timeout".into()));
            }
            tokio::select! {
                _=self.start_retry_wake.notified()=>self.ensure_start_not_cancelled(epoch)?,
                _=tokio::time::sleep(Duration::from_millis(100))=>(),
            }
            snapshot = self
                .tunnel
                .desktop_redundancy_command(Command::Status {
                    scope: scope.clone(),
                })
                .await?;
        }
    }

    async fn send_desktop_member(
        &self,
        command: Command,
        epoch: StartCancellationEpoch,
        wake_stamp: Option<i64>,
        allowed: impl Fn() -> bool + Send + Sync + 'static,
        candidate_clock: Option<&CandidateLeaseClock>,
    ) -> Result<Option<nelomai_client_tunnel::redundancy::protocol::Snapshot>, CoreError> {
        // Stop signals cancellation before acquiring the writer gate. DNS must
        // release that gate promptly and must never submit a late member start.
        let command = self
            .await_with_start_cancellation(
                Some(epoch),
                super::desktop_endpoint::pin_command(command),
            )
            .await?;
        if !allowed() {
            return Ok(None);
        }
        self.dispatch_desktop_recovery_command(
            command?,
            epoch,
            wake_stamp,
            allowed,
            candidate_clock,
        )
        .await
    }

    fn desktop_dispatch_allowed(
        &self,
        epoch: StartCancellationEpoch,
        recovery_allowed: impl Fn() -> bool + Send + Sync + 'static,
    ) -> impl Fn() -> bool + Send + Sync + 'static {
        let current_epoch = self.start_cancel_epoch.clone();
        let stop_gate = self.local_stop_gate.clone();
        move || {
            recovery_allowed()
                && current_epoch.load(Ordering::SeqCst) == epoch.0
                && stop_gate.try_lock().is_ok()
        }
    }

    #[cfg(target_os = "macos")]
    pub(super) fn desktop_epoch_cancelled(
        &self,
        epoch: StartCancellationEpoch,
    ) -> impl Future<Output = ()> + Send + 'static {
        let current_epoch = self.start_cancel_epoch.clone();
        let wake = self.start_retry_wake.clone();
        async move {
            loop {
                let notified = wake.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if current_epoch.load(Ordering::SeqCst) != epoch.0 {
                    return;
                }
                notified.await;
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn desktop_wake_guard(
        &self,
        epoch: StartCancellationEpoch,
        stamp: Option<i64>,
        allowed: impl Fn() -> bool + Send + 'static,
    ) -> nelomai_client_tunnel::WakeDispatchGuard {
        nelomai_client_tunnel::WakeDispatchGuard::new(stamp, allowed)
            .with_cancellation(self.desktop_epoch_cancelled(epoch))
    }

    async fn dispatch_desktop_recovery_command(
        &self,
        command: Command,
        _epoch: StartCancellationEpoch,
        _wake_stamp: Option<i64>,
        allowed: impl Fn() -> bool + Send + Sync + 'static,
        candidate_clock: Option<&CandidateLeaseClock>,
    ) -> Result<Option<nelomai_client_tunnel::redundancy::protocol::Snapshot>, CoreError> {
        #[cfg(target_os = "macos")]
        let uptime_deadline = match candidate_clock {
            Some(clock) => {
                // Both sides of native IPC must be able to enforce the same bound.
                let Some(start) = clock.uptime_at_start else {
                    return Ok(None);
                };
                Some(start + CANDIDATE_LEASE_WINDOW)
            }
            None => None,
        };
        let clock = candidate_clock.cloned();
        let admitted = move || allowed() && clock.as_ref().is_none_or(|clock| !clock.expired());
        if !admitted() {
            return Ok(None);
        }
        #[cfg(target_os = "macos")]
        let result = {
            let guard = self
                .desktop_wake_guard(_epoch, _wake_stamp, admitted)
                .with_uptime_deadline(uptime_deadline);
            match self
                .tunnel
                .desktop_redundancy_command_guarded(command, guard)
                .await
            {
                Err(TunnelError::Backend(code))
                    if code == nelomai_client_tunnel::WAKE_DISPATCH_DEFERRED =>
                {
                    return Ok(None)
                }
                result => result,
            }
        };
        #[cfg(not(target_os = "macos"))]
        let result = self.tunnel.desktop_redundancy_command(command).await;
        result.map(Some).map_err(Into::into)
    }
}

fn canonical_role_request(
    snapshot: &nelomai_client_tunnel::redundancy::protocol::Snapshot,
) -> Result<RedundantRoleRequest, CoreError> {
    let active = if snapshot.session.active == nelomai_client_tunnel::redundancy::Slot::A {
        0
    } else {
        1
    };
    Ok(RedundantRoleRequest {
        session_id: snapshot.session.scope.session_id.clone(),
        active_lease_id: snapshot.current_leases[active]
            .clone()
            .ok_or(CoreError::Storage)?,
        expected_role_generation: snapshot.session.role_generation,
        expected_membership_generation: snapshot.session.membership_generation,
        reason: None,
        observed_at: None,
    })
}

/// The privileged helper can acknowledge a validated panel reply just before
/// the app's protected write fails. Its exact scoped committed map is then the
/// receipt; never synthesize authority from an interface name or old config.
fn sync_helper_ack(
    pair: &mut StoredDesktopRedundancy,
    runtime: nelomai_contracts::RuntimeSlot,
    snapshot: &nelomai_client_tunnel::redundancy::protocol::Snapshot,
) -> Result<bool, CoreError> {
    let mut next = pair.clone();
    if snapshot.session.role_generation != pair.session.role_generation {
        if pair.session.role_generation.checked_add(1) != Some(snapshot.session.role_generation) {
            return Err(invalid_operation_reconcile_response());
        }
        next.session.role_generation = snapshot.session.role_generation;
    }
    let advanced = snapshot.session.membership_generation != pair.session.membership_generation;
    let recommitted = pair.candidate.as_ref().is_some_and(|candidate| {
        let i = if candidate.candidate_slot == RedundancyMemberSlot::A {
            0
        } else {
            1
        };
        candidate.reused
            && snapshot.session.committed[i]
            && snapshot.current_leases[i].as_deref() == Some(candidate.candidate_lease_id.as_str())
            && pair
                .pending_acquire
                .as_ref()
                .and_then(|p| p.replace_lease_id.as_deref())
                == Some(candidate.candidate_lease_id.as_str())
    });
    if advanced {
        let candidate = pair.candidate.as_ref().ok_or(CoreError::Storage)?;
        let index = if candidate.candidate_slot == RedundancyMemberSlot::A {
            0
        } else {
            1
        };
        if pair.session.membership_generation.checked_add(1)
            != Some(snapshot.session.membership_generation)
            || !snapshot.session.committed[index]
            || snapshot.leases[index].as_deref() != Some(candidate.candidate_lease_id.as_str())
        {
            return Err(invalid_operation_reconcile_response());
        }
        next.session.membership_generation = snapshot.session.membership_generation;
    }
    desktop_redundancy::validate_snapshot(&next, runtime, snapshot)?;
    if advanced || recommitted {
        let candidate = next.candidate.take().ok_or(CoreError::Storage)?;
        match candidate.candidate_slot {
            RedundancyMemberSlot::A => next.connection = candidate.connection,
            RedundancyMemberSlot::B => {
                next.session.standby = Some(nelomai_contracts::RedundancyMember {
                    health: nelomai_contracts::RedundancyMemberHealth::Warming,
                    connection: candidate.connection,
                    configuration: candidate.configuration,
                    health_probe: candidate.health_probe,
                })
            }
        }
        next.pending_acquire = None;
    }
    let changed = &next != pair;
    *pair = next;
    Ok(changed)
}

#[cfg(test)]
mod candidate_clock_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn candidate_expires_at_monotonic_deadline_even_when_tokio_time_is_paused() {
        let mut clock = CandidateLeaseClock::start("operation");
        let uptime = Duration::from_secs(4_000);
        clock.uptime_at_start = Some(uptime);

        assert!(!clock.expired_at(Some(uptime)));
        assert!(!clock.expired_at(Some(
            uptime + CANDIDATE_LEASE_WINDOW - Duration::from_nanos(1)
        )));
        assert!(clock.expired_at(Some(uptime + CANDIDATE_LEASE_WINDOW)));
    }

    #[tokio::test(start_paused = true)]
    async fn candidate_uses_tokio_elapsed_time_if_uptime_is_unavailable() {
        let clock = CandidateLeaseClock::start("operation");

        assert!(!clock.expired_at(None));
        tokio::time::advance(CANDIDATE_LEASE_WINDOW).await;
        assert!(clock.expired_at(None));
    }
}
