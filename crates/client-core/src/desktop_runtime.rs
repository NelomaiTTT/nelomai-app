//! Desktop orchestration under the existing Core writer gates. Native health
//! and failover live in the helper; neither requires these panel calls to run.
use super::*;
use nelomai_client_storage::{RuntimeAuthScope, StoredDesktopRedundancy};
use nelomai_client_tunnel::{
    redundancy::{protocol::Command, session::SessionPhase},
    DesktopTunnelOptions,
};
use nelomai_contracts::RedundancySession;

impl<A: CoreApi, S: RuntimeStateStore, T: TunnelController, L: CoreLogger> ClientCore<A, S, T, L> {
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
        let Ok(_sync) = self.desktop_sync_gate.try_lock() else {
            return Ok(None);
        };
        let (stored, pair, snapshot, access) = {
            let _writer = self.connection_gate.lock().await;
            let mut stored = self.load_runtime()?;
            let Some(mut pair) = stored.desktop_redundancy.clone() else {
                return Ok(None);
            };
            if pair.stop.is_some() || stored.pending_compensation_stop.is_some() {
                return Ok(None);
            }
            let access = self.access_snapshot().await?;
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
                .await?;
            if sync_helper_ack(&mut pair, stored.slot, &snapshot)? {
                stored.desktop_redundancy = Some(pair.clone());
                self.store.save(&stored).map_err(|_| CoreError::Storage)?;
            }
            desktop_redundancy::validate_snapshot(&pair, stored.slot, &snapshot)?;
            if snapshot.session.phase != SessionPhase::Running || snapshot.cleanup_pending {
                return Ok(Some(snapshot));
            }
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
                    .tunnel
                    .desktop_redundancy_command(command)
                    .await
                    .map(Some)
                    .map_err(Into::into);
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
                        .tunnel
                        .desktop_redundancy_command(command)
                        .await
                        .map(Some)
                        .map_err(Into::into);
                }
                if let Some(candidate) = pair.candidate.as_ref() {
                    if snapshot.leases[inactive].is_none() {
                        let command = desktop_redundancy::stage_command(
                            &pair,
                            stored.slot,
                            &snapshot,
                            candidate,
                        )?;
                        return self
                            .tunnel
                            .desktop_redundancy_command(command)
                            .await
                            .map(Some)
                            .map_err(Into::into);
                    }
                } else if snapshot.leases[inactive].is_none()
                    && pair.session.standby_desired
                    && pair.pending_acquire.is_none()
                {
                    pair.pending_acquire = Some(desktop_redundancy::acquire_request(
                        &pair,
                        stored.slot,
                        &snapshot,
                        &Uuid::new_v4().to_string(),
                        probes,
                    )?);
                    stored.desktop_redundancy = Some(pair.clone());
                    self.store.save(&stored).map_err(|_| CoreError::Storage)?;
                }
            }
            (stored, pair, snapshot, access)
        };
        if !pair.primary_reported && snapshot.primary_ready {
            let request = RedundantRoleRequest {
                session_id: pair.session.session_id.clone(),
                active_lease_id: pair.connection.lease_id.clone(),
                expected_role_generation: pair.session.role_generation,
                expected_membership_generation: pair.session.membership_generation,
                reason: Some("primary_ready".into()),
                observed_at: None,
            };
            let response = self.api.report_redundant_role(&access, &request).await?;
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
            if current.auth_scope != stored.auth_scope
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
        } else if !snapshot.session.role_confirmed {
            let request = desktop_redundancy::role_request(&snapshot)?;
            let response = self.api.report_redundant_role(&access, &request).await?;
            let _writer = self.connection_gate.lock().await;
            let mut current = self.load_runtime()?;
            if current.auth_scope != stored.auth_scope
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
                .await?;
            desktop_redundancy::validate_snapshot(&pair, current.slot, &fresh)?;
            let command = desktop_redundancy::confirm_role_command(&fresh, &response)?;
            let confirmed = self.tunnel.desktop_redundancy_command(command).await?;
            let mut next = pair.clone();
            next.session.role_generation = response.session.role_generation;
            desktop_redundancy::validate_snapshot(&next, current.slot, &confirmed)?;
            current.desktop_redundancy = Some(next);
            self.store.save(&current).map_err(|_| CoreError::Storage)?;
            return Ok(Some(confirmed));
        } else if pair.primary_reported && snapshot.primary_ready && pair.candidate.is_none() {
            if let Some(request) = pair.pending_acquire.as_ref() {
                let response = self.api.acquire_redundant_standby(&access, request).await?;
                let _writer = self.connection_gate.lock().await;
                let mut current = self.load_runtime()?;
                if current.auth_scope != stored.auth_scope
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
                    .await?;
                let mut next = pair.clone();
                next.candidate = Some(response.clone());
                // Validate before persistence; Stage happens on a later step.
                desktop_redundancy::stage_command(&next, current.slot, &fresh, &response)?;
                current.desktop_redundancy = Some(next);
                self.store.save(&current).map_err(|_| CoreError::Storage)?;
            }
        } else if pair.primary_reported && pair.candidate.is_some() && snapshot.standby_ready {
            let request = desktop_redundancy::commit_request(&pair, stored.slot, &snapshot)?;
            let response = match self.api.commit_redundant_candidate(&access, &request).await {
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
                        .await?;
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
            if current.auth_scope != stored.auth_scope
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
                .await?;
            let command =
                desktop_redundancy::commit_command(&pair, current.slot, &fresh, &response)?;
            let committed = self.tunnel.desktop_redundancy_command(command).await?;
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
        if !observed.stalled
            || observed.primary_ready
            || !matches!(
                observed.session.phase,
                SessionPhase::Running | SessionPhase::Stopping | SessionPhase::Stopped
            )
        {
            return Ok(false);
        }
        // No global cancellation from a stale background observation. Both the
        // protected owner and the helper's atomic health/revision fence must match.
        let _intent = self.intent_recovery_gate.lock().await;
        let _split = self.split_tunnel_gate.lock().await;
        let _writer = self.connection_gate.lock().await;
        let stored = self.load_runtime()?;
        let Some(pair) = stored.desktop_redundancy.as_ref() else {
            return Ok(false);
        };
        desktop_redundancy::validate_snapshot(pair, stored.slot, observed)?;
        if pair.stop.is_some() || stored.pending_compensation_stop.is_some() {
            // An exact accepted cold request can outlive its first caller.
            // A retaining/manual request or unrelated compensation must not
            // become automatic-recovery authority through this retry.
            return Ok(pair
                .stop
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
                }));
        }
        // A previous freeze may have closed native traffic before a protected
        // journal write failed. Retry the same helper-fenced cold cleanup; a
        // stopped snapshot alone never authorizes a new Start or WARM retention.
        let frozen = self
            .tunnel
            .desktop_redundancy_command(Command::PrepareRecoveryStop {
                scope: observed.session.scope.clone(),
                expected_revision: observed.session.local_revision,
                expected_network_epoch: observed.session.network_epoch,
            })
            .await?;
        self.stop_desktop_with_frozen(stored, Some(frozen), false)
            .await?;
        Ok(true)
    }

    pub(super) async fn stop_desktop_locally(
        &self,
        stored: nelomai_client_storage::RuntimeStateV1,
    ) -> Result<Connection, CoreError> {
        self.stop_desktop_with_frozen(stored, None, true).await
    }

    async fn stop_desktop_with_frozen(
        &self,
        mut stored: nelomai_client_storage::RuntimeStateV1,
        frozen: Option<nelomai_client_tunnel::redundancy::protocol::Snapshot>,
        ordinary: bool,
    ) -> Result<Connection, CoreError> {
        let mut pair = stored
            .desktop_redundancy
            .clone()
            .ok_or(CoreError::Storage)?;
        let scope = desktop_redundancy::scope(&pair, stored.slot)?;
        self.set_phase(Phase::Stopping).await;
        *self.active_recovery_episode.lock().await = None;
        let journal = async {
            let stop = if let Some(stop) = pair.stop.clone() {
                stop
            } else {
                // A compensation request already sent must not change its lease
                // or retention payload into an ordinary warm Stop on retry.
                if stored.pending_compensation_stop.is_some() {
                    return Err(CoreError::Storage);
                }
                let prepared = match frozen {
                    Some(frozen) => Ok(frozen),
                    None => {
                        self.tunnel
                            .desktop_redundancy_command(Command::PrepareStop {
                                scope: scope.clone(),
                            })
                            .await
                    }
                };
                match prepared {
                    Ok(frozen) => {
                        sync_helper_ack(&mut pair, stored.slot, &frozen)?;
                        stored.desktop_redundancy = Some(pair.clone());
                        desktop_redundancy::stop_record(
                            &pair,
                            stored.slot,
                            &frozen,
                            &Uuid::new_v4().to_string(),
                            ordinary && frozen.session.phase == SessionPhase::Stopping,
                        )?
                    }
                    Err(error) => {
                        if !self.tunnel.desktop_redundancy_absent().await? {
                            return Err(error.into());
                        }
                        // Restart cleanup has no frozen last-active proof. Full
                        // server Stop accepts a historical member of this exact
                        // session; never infer a WARM role from protected metadata.
                        nelomai_client_storage::StoredDesktopRedundantStop {
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
        let close_result = {
            let first_request = async {
                if let Ok((_, stop)) = &journal {
                    // An unreported native promotion needs role reconciliation
                    // first. Closing locally never waits for that round trip.
                    if !stop.retain_active_peer || stop.role_confirmed {
                        if let Ok(access) = self.access_snapshot().await {
                            let _ = self
                                .api
                                .stop_redundant_connection(
                                    &access,
                                    &RedundantStopRequest {
                                        operation_id: stop.operation_id.clone(),
                                        lease_id: stop.active_lease_id.clone(),
                                        session_id: pair.session.session_id.clone(),
                                        recovery_contract_version: RecoveryContractV2,
                                        retain_active_peer: stop.retain_active_peer,
                                    },
                                )
                                .await;
                        }
                    }
                }
            };
            tokio::pin!(first_request);
            let close = self.close_desktop_pair(scope);
            tokio::pin!(close);
            tokio::select! {
                biased;
                _=&mut first_request=>close.await,
                result=&mut close=>result,
            }
        };
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
        epoch: StartCancellationEpoch,
        required: bool,
    ) -> Result<(), CoreError> {
        // Android and old/single helpers retain their original path. The desktop
        // reserve admission checks capability BEFORE obtaining a server lease.
        if !required {
            return self.tunnel.start(request).await.map_err(Into::into);
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
        let mut stored = self.load_runtime()?;
        if stored.auth_scope.as_ref() != Some(&auth_scope) || stored.desktop_redundancy.is_some() {
            return Err(CoreError::Storage);
        }
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
        let scope = desktop_redundancy::scope(&pair, stored.slot)?;
        let command = desktop_redundancy::primary_command(
            &pair,
            stored.slot,
            request.configuration,
            DesktopTunnelOptions::from_tunnel_options(&request.options),
            primary_probe,
        )?;
        stored.desktop_redundancy = Some(pair.clone());
        self.store.save(&stored).map_err(|_| CoreError::Storage)?;
        self.ensure_start_not_cancelled(epoch)?;
        let mut snapshot = self.tunnel.desktop_redundancy_command(command).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            self.ensure_start_not_cancelled(epoch)?;
            desktop_redundancy::validate_snapshot(&pair, stored.slot, &snapshot)?;
            if snapshot.session.phase != SessionPhase::Running || snapshot.cleanup_pending {
                return Err(CoreError::Tunnel("redundancy_primary_stopped".into()));
            }
            if snapshot.primary_ready {
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
