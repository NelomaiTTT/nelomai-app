use super::{transport::*, *};
use crate::{AuthBroker, BrokerAuthState, BrokerError, LocalAuthStop, RuntimeClientProfile};
use async_trait::async_trait;
use nelomai_client_api::{LoginRequest, RuntimeTarget};
use nelomai_client_core::{CoreError, RuntimeAuthProvider};
use nelomai_client_storage::BrokerRequestV1;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, Semaphore};

/// Trusted native/desktop dispatcher in the owner only. Protected requests and
/// callback credentials terminate here; runtime sees action/status/access only.
#[async_trait]
pub trait PrivateBackgroundDispatcher: Send + Sync {
    async fn cleanup_push(&self) -> Result<(), BrokerError> {
        Err(BrokerError::RecoveryRequired)
    }
    /// Existing owner/native cleanup handoff, never a runtime-provided ticket.
    async fn prepare_revocation(&self, cancel_epoch: u64) -> Result<(), BrokerError>;
    async fn dispatch(
        &self,
        request: crate::NativeAuthRequest,
        action: BackgroundAction,
    ) -> Result<Option<nelomai_client_api::TokenResponse>, crate::NativeAuthFailure>;
}

/// Opaque association minted by the trusted launcher after file verification
/// and actual child endpoint transfer. There is deliberately no production
/// hash/PID constructor: Task9 must implement that verified factory.
pub struct LaunchBinding {
    target: RuntimeTarget,
    incarnation: String,
}
impl LaunchBinding {
    pub(crate) fn from_common_host(target: RuntimeTarget, incarnation: String) -> Self {
        Self {
            target,
            incarnation,
        }
    }
    #[cfg(test)]
    pub(super) fn fixture(target: RuntimeTarget, incarnation: &str) -> Self {
        Self {
            target,
            incarnation: incarnation.into(),
        }
    }
}

pub struct RemoteOwner {
    binding: LaunchBinding,
    profile: RuntimeClientProfile,
    pub(super) outbox: Arc<Outbox>,
    acks: Arc<Pending<ControlAckV1>>,
    incoming: Mutex<Option<mpsc::Receiver<(FrameV1, Instant)>>>,
    pub(super) logins: Mutex<HashMap<u64, (ScopeStamp, Option<BrokerRequestV1>)>>,
    background: Option<Arc<dyn PrivateBackgroundDispatcher>>,
    commands: Option<Arc<dyn crate::host::PrivateOwnerCommands>>,
}
#[cfg(test)]
pub(super) fn acknowledge_test_control(owner: &RemoteOwner, id: u64, ack: ControlAckV1) {
    owner.acks.finish(id, ack).unwrap();
}
struct LoginAssociation<'a> {
    owner: &'a RemoteOwner,
    id: u64,
}
struct AdmissionLease<'a> {
    owner: &'a RemoteOwner,
    lease: PreparedLease,
    granted: bool,
}

struct RemoteCleanupLease {
    outbox: Arc<Outbox>,
    lease: PreparedLease,
}
impl Drop for RemoteCleanupLease {
    fn drop(&mut self) {
        let result = self.outbox.id().and_then(|id| {
            self.outbox.enqueue(
                FrameV1::new(
                    id,
                    MessageV1::Control(ControlV1::Abort {
                        lease: self.lease.clone(),
                    }),
                ),
                Instant::now() + REQUEST_BUDGET,
            )
        });
        if result.is_err() {
            self.outbox.close();
        }
    }
}
impl Drop for AdmissionLease<'_> {
    fn drop(&mut self) {
        if !self.granted {
            let result = self.owner.outbox.id().and_then(|id| {
                self.owner.outbox.enqueue(
                    FrameV1::new(
                        id,
                        MessageV1::Control(ControlV1::Abort {
                            lease: self.lease.clone(),
                        }),
                    ),
                    Instant::now() + REQUEST_BUDGET,
                )
            });
            if result.is_err() {
                self.owner.outbox.close();
            }
        }
    }
}
impl Drop for LoginAssociation<'_> {
    fn drop(&mut self) {
        if let Ok(mut logins) = self.owner.logins.lock() {
            logins.remove(&self.id);
        }
    }
}
struct ClientLoginAssociation<'a> {
    pending: &'a Mutex<Option<u64>>,
    id: Option<u64>,
}
impl Drop for ClientLoginAssociation<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            if let Ok(mut pending) = self.pending.lock() {
                if *pending == Some(id) {
                    *pending = None;
                }
            }
        }
    }
}
pub struct OwnerService {
    outbox: Arc<Outbox>,
}
impl Drop for OwnerService {
    fn drop(&mut self) {
        self.outbox.close();
    }
}
impl Drop for RemoteOwner {
    fn drop(&mut self) {
        self.outbox.close();
    }
}

impl RemoteOwner {
    pub fn is_connected(&self) -> bool {
        !self.outbox.is_closed()
    }
    pub fn new<S>(
        stream: S,
        binding: LaunchBinding,
        profile: RuntimeClientProfile,
    ) -> Result<Arc<Self>, PrivateError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new_with_background(stream, binding, profile, None)
    }
    pub fn new_with_background<S>(
        stream: S,
        binding: LaunchBinding,
        profile: RuntimeClientProfile,
        background: Option<Arc<dyn PrivateBackgroundDispatcher>>,
    ) -> Result<Arc<Self>, PrivateError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::new_with_owner(stream, binding, profile, background, None)
    }
    pub fn new_with_owner<S>(
        stream: S,
        binding: LaunchBinding,
        profile: RuntimeClientProfile,
        background: Option<Arc<dyn PrivateBackgroundDispatcher>>,
        commands: Option<Arc<dyn crate::host::PrivateOwnerCommands>>,
    ) -> Result<Arc<Self>, PrivateError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        binding
            .target
            .identity(None)
            .map_err(|_| PrivateError::Protocol)?;
        if binding.incarnation.is_empty() || binding.incarnation.len() > 128 {
            return Err(PrivateError::Protocol);
        }
        let (outbox, incoming) = connect(stream);
        Ok(Arc::new(Self {
            binding,
            profile,
            outbox,
            acks: Arc::new(Pending::default()),
            incoming: Mutex::new(Some(incoming)),
            logins: Mutex::new(HashMap::new()),
            background,
            commands,
        }))
    }
    pub fn revoke_peer(&self) {
        self.outbox.close();
    }
    fn live(&self, deadline: Instant) -> Result<(), PrivateError> {
        if self.outbox.is_closed() {
            return Err(PrivateError::Closed);
        }
        if Instant::now() >= deadline {
            return Err(PrivateError::Timeout);
        }
        Ok(())
    }
    pub(super) async fn control(
        &self,
        control: ControlV1,
        deadline: Instant,
    ) -> Result<ControlAckV1, PrivateError> {
        self.live(deadline)?;
        let mut lifetime = RequestLifetime {
            outbox: self.outbox.clone(),
            complete: false,
        };
        let id = self.outbox.id()?;
        let receiver = self.acks.insert(id)?;
        self.outbox
            .enqueue(FrameV1::new(id, MessageV1::Control(control)), deadline)?;
        let mut cancel = self.outbox.cancellation();
        let result = tokio::select! { biased;
            _ = closed(&mut cancel) => Err(PrivateError::Closed),
            result = timeout_at(deadline, receiver) => result.map_err(|_| PrivateError::Timeout)?.map_err(|_| PrivateError::Closed),
        }?;
        if matches!(&result, ControlAckV1::Prepared { lease } if lease.request != id || lease.incarnation != self.binding.incarnation)
        {
            return Err(PrivateError::Protocol);
        }
        lifetime.complete = true;
        match result {
            ControlAckV1::Error { error } => Err(error),
            ack => Ok(ack),
        }
    }
    fn enqueue_revoke(&self) {
        // Saturation closes the peer but cannot suppress the broker's stop or
        // revocation HTTP. This synchronous callback deliberately cannot fail.
        let result = self.outbox.id().and_then(|id| {
            self.outbox.enqueue(
                FrameV1::new(id, MessageV1::Control(ControlV1::Revoke)),
                Instant::now() + REQUEST_BUDGET,
            )
        });
        if result.is_err() {
            self.outbox.close();
        }
    }
    pub fn serve(self: &Arc<Self>, broker: Arc<AuthBroker>) -> Result<OwnerService, PrivateError> {
        let mut incoming = self
            .incoming
            .lock()
            .map_err(|_| PrivateError::Closed)?
            .take()
            .ok_or(PrivateError::Protocol)?;
        let owner = self.clone();
        let mut cancel = self.outbox.cancellation();
        tokio::spawn(async move {
            let slots = Arc::new(Semaphore::new(MAX_PENDING));
            let mut operations = tokio::task::JoinSet::new();
            // Logout already accepted by this pump owns its bounded completion;
            // peer EOF or dropping a client waiter cannot abort durable cleanup.
            let mut logouts = tokio::task::JoinSet::new();
            loop {
                let (frame, deadline) = tokio::select! { biased;
                    _ = closed(&mut cancel) => break,
                    Some(_) = operations.join_next(), if !operations.is_empty() => continue,
                    Some(_) = logouts.join_next(), if !logouts.is_empty() => continue,
                    frame = incoming.recv() => match frame { Some(frame) => frame, None => break },
                };
                if Instant::now() >= deadline {
                    break;
                }
                match frame.message {
                    MessageV1::Ack(ack) => {
                        if owner.acks.finish(frame.id, ack).is_err() {
                            break;
                        }
                    }
                    MessageV1::Request(request) => {
                        let Ok(permit) = slots.clone().try_acquire_owned() else {
                            break;
                        };
                        let is_logout = matches!(request, AuthRequestV1::Logout { .. });
                        let owner = owner.clone();
                        let broker = broker.clone();
                        let task = async move {
                            let _permit = permit;
                            let result = timeout_at(
                                deadline,
                                owner.request(&broker, frame.id, request, deadline),
                            )
                            .await;
                            let result = result.unwrap_or(Err(PrivateError::Timeout));
                            if let Err(error) = result {
                                let _ = owner.outbox.enqueue(
                                    FrameV1::new(
                                        frame.id,
                                        MessageV1::Response(AuthResponseV1::Error { error }),
                                    ),
                                    deadline,
                                );
                            }
                        };
                        if is_logout {
                            logouts.spawn(task);
                        } else {
                            operations.spawn(task);
                        }
                    }
                    _ => break,
                }
            }
            owner.outbox.close();
            owner.acks.clear();
            operations.abort_all();
            while operations.join_next().await.is_some() {}
            while logouts.join_next().await.is_some() {}
        });
        Ok(OwnerService {
            outbox: self.outbox.clone(),
        })
    }
    pub(super) async fn prepare(&self, deadline: Instant) -> Result<PreparedLease, PrivateError> {
        match self
            .control(
                ControlV1::Prepare {
                    incarnation: self.binding.incarnation.clone(),
                },
                deadline,
            )
            .await?
        {
            ControlAckV1::Prepared { lease } if lease.incarnation == self.binding.incarnation => {
                Ok(lease)
            }
            _ => Err(PrivateError::Protocol),
        }
    }
    async fn commit_and_grant(
        &self,
        broker: &AuthBroker,
        access: AccessSnapshot,
        lease: PreparedLease,
        reply_to: Option<u64>,
        deadline: Instant,
    ) -> Result<(), PrivateError> {
        self.check_target(&access)?;
        let scope = scope(&access);
        match self
            .control(
                ControlV1::CommitAdmission {
                    lease: lease.clone(),
                    scope: scope.clone(),
                },
                deadline,
            )
            .await?
        {
            ControlAckV1::Committed => {}
            _ => return Err(PrivateError::Protocol),
        }
        self.grant_committed(broker, access, lease, reply_to, deadline)
            .await
    }

    async fn grant_committed(
        &self,
        broker: &AuthBroker,
        access: AccessSnapshot,
        lease: PreparedLease,
        reply_to: Option<u64>,
        deadline: Instant,
    ) -> Result<(), PrivateError> {
        self.check_target(&access)?;
        let scope = scope(&access);
        broker
            .with_current_access(&access, || {
                // Only lock-free checks and bounded synchronous enqueue occur in
                // this closure. The child still holds guards and CLOSED latch.
                self.live(deadline).map_err(|_| BrokerError::Cancelled)?;
                let response = reply_to.map(|id| {
                    (
                        id,
                        AuthResponseV1::Access {
                            stamp: ScopeStamp::from_access(&access),
                            access: access.clone(),
                        },
                    )
                });
                let id = self.outbox.id().map_err(|_| BrokerError::Cancelled)?;
                self.outbox
                    .enqueue(
                        FrameV1::new(
                            id,
                            MessageV1::Control(ControlV1::Grant {
                                lease,
                                scope,
                                response: Box::new(response),
                            }),
                        ),
                        deadline,
                    )
                    .map_err(|_| BrokerError::Cancelled)
            })
            .await
            .map_err(broker_error)
    }

    pub async fn runtime_cleanup_handoff(
        &self,
        source: &crate::TransitionSourceSnapshot,
    ) -> Result<crate::RuntimeCleanupHandoff, PrivateError> {
        let deadline = Instant::now() + REQUEST_BUDGET;
        let lease = self.prepare(deadline).await?;
        let held = RemoteCleanupLease {
            outbox: self.outbox.clone(),
            lease: lease.clone(),
        };
        let source_scope = source.identity().map(|identity| RuntimeAuthScope {
            auth_epoch: source.auth_epoch(),
            family: source.family().into(),
            identity: identity.clone(),
        });
        let snapshot = match self
            .control(
                ControlV1::CleanupSourceSnapshot {
                    lease,
                    scope: source_scope,
                },
                deadline,
            )
            .await?
        {
            ControlAckV1::CleanupSnapshot { snapshot } => snapshot,
            _ => return Err(PrivateError::Protocol),
        };
        if !source.matches_runtime_scope(snapshot.auth_scope.as_ref())
            || source.identity().is_some_and(|identity| {
                identity.slot != snapshot.slot
                    || identity.runtime_version != snapshot.runtime_version
            })
        {
            return Err(PrivateError::RecoveryRequired);
        }
        Ok(crate::RuntimeCleanupHandoff::remote(snapshot, held))
    }

    pub async fn complete_runtime_cleanup(
        &self,
        broker: &AuthBroker,
        snapshot: &nelomai_client_storage::RuntimeCleanupSnapshotV1,
        access: &AccessSnapshot,
    ) -> Result<(), PrivateError> {
        self.check_target(access)?;
        let deadline = Instant::now() + REQUEST_BUDGET;
        let lease = self.prepare(deadline).await?;
        let mut held = AdmissionLease {
            owner: self,
            lease: lease.clone(),
            granted: false,
        };
        match self
            .control(
                ControlV1::CompleteCleanup {
                    lease: lease.clone(),
                    snapshot: snapshot.clone(),
                    scope: scope(access),
                },
                deadline,
            )
            .await?
        {
            ControlAckV1::Committed => {}
            _ => return Err(PrivateError::Protocol),
        }
        self.grant_committed(broker, access.clone(), lease, None, deadline)
            .await?;
        held.granted = true;
        Ok(())
    }
    /// Explicit startup/control admission. Read-only state/access never binds a
    /// missing runtime scope. The actual child record is the only full writer.
    pub async fn admit_empty_current(&self, broker: &AuthBroker) -> Result<(), PrivateError> {
        self.admit_current_after(broker, || Ok(())).await
    }
    pub(crate) async fn admit_current_after(
        &self,
        broker: &AuthBroker,
        finish: impl FnOnce() -> Result<(), PrivateError> + Send,
    ) -> Result<(), PrivateError> {
        let deadline = Instant::now() + REQUEST_BUDGET;
        timeout_at(deadline, async {
            let lease = self.prepare(deadline).await?;
            let mut held = AdmissionLease {
                owner: self,
                lease: lease.clone(),
                granted: false,
            };
            let observation = broker.observe().await.map_err(broker_error)?;
            let access = observation.access.ok_or(PrivateError::RecoveryRequired)?;
            broker
                .with_current_access(&access, || {
                    finish().map_err(|_| BrokerError::RecoveryRequired)
                })
                .await
                .map_err(broker_error)?;
            self.commit_and_grant(broker, access, lease, None, deadline)
                .await?;
            held.granted = true;
            Ok(())
        })
        .await
        .map_err(|_| PrivateError::Timeout)?
    }
    fn check_target(&self, access: &AccessSnapshot) -> Result<(), PrivateError> {
        if RuntimeTarget::from_identity(access.identity()) == self.binding.target {
            Ok(())
        } else {
            Err(PrivateError::Cancelled)
        }
    }
    pub(crate) async fn recover_logout(
        &self,
        broker: &AuthBroker,
        coordinator: &crate::SwitchCoordinator,
    ) -> Result<(), PrivateError> {
        let _execution = coordinator.lock_logout_cleanup().await;
        let Some(receipt) = broker
            .completed_runtime_logout()
            .await
            .map_err(broker_error)?
        else {
            return Ok(());
        };
        let deadline = Instant::now() + REQUEST_BUDGET;
        let lease = self.prepare(deadline).await?;
        let _held = AdmissionLease {
            owner: self,
            lease: lease.clone(),
            granted: false,
        };
        broker
            .stop_runtime_logout_cleanup(&receipt)
            .await
            .map_err(broker_error)?;
        match self
            .control(
                ControlV1::CompleteLogout {
                    lease,
                    receipt: receipt.clone(),
                },
                deadline,
            )
            .await?
        {
            ControlAckV1::Done => {}
            _ => return Err(PrivateError::RecoveryRequired),
        }
        coordinator
            .retire_logout_journal(&receipt)
            .await
            .map_err(|_| PrivateError::RecoveryRequired)?;
        broker
            .finish_runtime_logout_cleanup(&receipt)
            .await
            .map_err(broker_error)
    }
    pub(super) async fn request(
        &self,
        broker: &AuthBroker,
        id: u64,
        request: AuthRequestV1,
        deadline: Instant,
    ) -> Result<(), PrivateError> {
        // Logout accepted before EOF may continue cleanup. Other requests never
        // issue after their peer is closed.
        if !matches!(request, AuthRequestV1::Logout { .. }) {
            self.live(deadline)?;
        }
        let response = match request {
            AuthRequestV1::Owner { request } => {
                let commands = self
                    .commands
                    .as_ref()
                    .ok_or(PrivateError::RecoveryRequired)?;
                let response = commands.dispatch(&self.binding.target, request).await?;
                self.live(deadline)?;
                AuthResponseV1::Owner { response }
            }
            AuthRequestV1::State => {
                let (stamp, observation) = broker.observe_stamped().await.map_err(broker_error)?;
                let state = match observation.state {
                    BrokerAuthState::Active => {
                        let access = observation.access.ok_or(PrivateError::RecoveryRequired)?;
                        self.check_target(&access)?;
                        if matches!(
                            self.control(
                                ControlV1::CheckScope {
                                    scope: scope(&access)
                                },
                                deadline
                            )
                            .await,
                            Ok(ControlAckV1::Done)
                        ) {
                            RuntimeAuthState::Active
                        } else {
                            RuntimeAuthState::RecoveryRequired
                        }
                    }
                    BrokerAuthState::LoggedOut => RuntimeAuthState::LoggedOut,
                    BrokerAuthState::LogoutPending => RuntimeAuthState::LogoutPending,
                    BrokerAuthState::RecoveryRequired => RuntimeAuthState::RecoveryRequired,
                    BrokerAuthState::AuthenticationOutcomeUnknown => {
                        RuntimeAuthState::AuthenticationOutcomeUnknown
                    }
                };
                AuthResponseV1::State { stamp, state }
            }
            AuthRequestV1::Login { stamp, request } => {
                let stamp = stamp.ok_or(PrivateError::Cancelled)?;
                let fence = broker
                    .capture_stamped_login_fence(Some(&stamp))
                    .await
                    .map_err(broker_error)?;
                {
                    let mut logins = self.logins.lock().map_err(|_| PrivateError::Closed)?;
                    if logins.len() >= MAX_PENDING || logins.contains_key(&id) {
                        return Err(PrivateError::Cancelled);
                    }
                    logins.insert(id, (stamp, None));
                }
                let _association = LoginAssociation { owner: self, id };
                let lease = self.prepare(deadline).await?;
                let mut held = AdmissionLease {
                    owner: self,
                    lease: lease.clone(),
                    granted: false,
                };
                self.live(deadline)?;
                let request = LoginRequest {
                    login: request.login,
                    password: request.password,
                    device_name: request.device_name,
                    install_secret: broker.owned_install_secret().map_err(broker_error)?,
                    platform: self.profile.platform,
                    platform_version: self.profile.platform_version.clone(),
                    architecture: self.profile.architecture.clone(),
                    app_version: self.binding.target.container_version.clone(),
                };
                let access = broker
                    .login_fenced_with_ticket(
                        &request,
                        &self.binding.target,
                        &fence,
                        || self.live(deadline).map_err(|_| BrokerError::Cancelled),
                        |ticket| {
                            // Lock order is broker state -> peer map. Logout clones
                            // from the map and drops it BEFORE acquiring broker state.
                            if let Ok(mut logins) = self.logins.lock() {
                                if let Some((_, pending)) = logins.get_mut(&id) {
                                    *pending = Some(ticket.clone());
                                }
                            }
                        },
                    )
                    .await
                    .map_err(broker_error)?;
                self.commit_and_grant(broker, access, lease, Some(id), deadline)
                    .await?;
                held.granted = true;
                return Ok(());
            }
            AuthRequestV1::AccessToken { stamp, stale } => {
                let stamp = stamp.ok_or(PrivateError::Cancelled)?;
                let (_, observation) = broker.observe_stamped().await.map_err(broker_error)?;
                let current = observation.access.ok_or(PrivateError::RecoveryRequired)?;
                self.check_target(&current)?;
                if stamp != ScopeStamp::from_access(&current) {
                    return Err(PrivateError::Cancelled);
                }
                if !matches!(
                    self.control(
                        ControlV1::CheckScope {
                            scope: scope(&current)
                        },
                        deadline
                    )
                    .await?,
                    ControlAckV1::Done
                ) {
                    return Err(PrivateError::Protocol);
                }
                self.live(deadline)?;
                let access = broker
                    .access_token_fenced_checked(&stamp, stale.as_ref(), || {
                        self.live(deadline).map_err(|_| BrokerError::Cancelled)
                    })
                    .await
                    .map_err(broker_error)?;
                self.check_target(&access)?;
                return broker
                    .with_current_access(&access, || {
                        self.live(deadline).map_err(|_| BrokerError::Cancelled)?;
                        self.outbox
                            .enqueue(
                                FrameV1::new(
                                    id,
                                    MessageV1::Response(AuthResponseV1::Access {
                                        stamp: ScopeStamp::from_access(&access),
                                        access: access.clone(),
                                    }),
                                ),
                                deadline,
                            )
                            .map_err(|_| BrokerError::Cancelled)
                    })
                    .await
                    .map_err(broker_error);
            }
            AuthRequestV1::Logout {
                stamp,
                cancel_login_request,
            } => {
                let stamp = stamp.ok_or(PrivateError::Cancelled)?;
                let pending = {
                    let logins = self.logins.lock().map_err(|_| PrivateError::Closed)?;
                    cancel_login_request
                        .and_then(|id| logins.get(&id))
                        .filter(|(original, _)| original == &stamp)
                        .and_then(|(_, ticket)| ticket.clone())
                };
                broker
                    .logout_pending_login_fenced(&stamp, pending.as_ref())
                    .await
                    .map_err(broker_error)?;
                if let Some(commands) = &self.commands {
                    commands
                        .dispatch(
                            &self.binding.target,
                            crate::host::HostRequestV1::RuntimeReady,
                        )
                        .await?;
                }
                AuthResponseV1::Done
            }
            AuthRequestV1::BackgroundCredential { stamp, action } => {
                let stamp = stamp.ok_or(PrivateError::Cancelled)?;
                let (current, observation) =
                    broker.observe_stamped().await.map_err(broker_error)?;
                if current != stamp {
                    return Err(PrivateError::Cancelled);
                }
                let expected_scope = stamp.runtime_scope().map_err(broker_error)?;
                if RuntimeTarget::from_identity(&expected_scope.identity) != self.binding.target {
                    return Err(PrivateError::Cancelled);
                }
                let mut recovery_lease = if matches!(action, BackgroundAction::Recover) {
                    Some(AdmissionLease {
                        owner: self,
                        lease: self.prepare(deadline).await?,
                        granted: false,
                    })
                } else {
                    None
                };
                let validation = match &recovery_lease {
                    Some(held) => ControlV1::ValidateScope {
                        lease: held.lease.clone(),
                        scope: expected_scope,
                    },
                    None => ControlV1::CheckScope {
                        scope: expected_scope,
                    },
                };
                if !matches!(
                    self.control(validation, deadline).await?,
                    ControlAckV1::Done
                ) {
                    return Err(PrivateError::Protocol);
                }
                if matches!(action, BackgroundAction::Status) {
                    return self.outbox.enqueue(
                        FrameV1::new(
                            id,
                            MessageV1::Response(AuthResponseV1::State {
                                stamp,
                                state: match observation.state {
                                    BrokerAuthState::Active => RuntimeAuthState::Active,
                                    BrokerAuthState::LoggedOut => RuntimeAuthState::LoggedOut,
                                    BrokerAuthState::LogoutPending => {
                                        RuntimeAuthState::LogoutPending
                                    }
                                    BrokerAuthState::AuthenticationOutcomeUnknown => {
                                        RuntimeAuthState::AuthenticationOutcomeUnknown
                                    }
                                    BrokerAuthState::RecoveryRequired => {
                                        RuntimeAuthState::RecoveryRequired
                                    }
                                },
                            }),
                        ),
                        deadline,
                    );
                }
                let native = self
                    .background
                    .as_ref()
                    .ok_or(PrivateError::RecoveryRequired)?;
                let access = broker
                    .native_auth_until(
                        |access| {
                            if ScopeStamp::from_access(access) != stamp {
                                return Err(BrokerError::Cancelled);
                            }
                            self.live(deadline).map_err(|_| BrokerError::Cancelled)
                        },
                        |request| native.dispatch(request, action),
                        matches!(action, BackgroundAction::Recover),
                        deadline,
                    )
                    .await
                    .map_err(broker_error)?;
                if let Some(held) = recovery_lease.as_mut() {
                    self.commit_and_grant(broker, access, held.lease.clone(), Some(id), deadline)
                        .await?;
                    held.granted = true;
                    return Ok(());
                }
                return broker
                    .with_current_access(&access, || {
                        self.live(deadline).map_err(|_| BrokerError::Cancelled)?;
                        self.outbox
                            .enqueue(
                                FrameV1::new(
                                    id,
                                    MessageV1::Response(AuthResponseV1::Access {
                                        stamp: ScopeStamp::from_access(&access),
                                        access: access.clone(),
                                    }),
                                ),
                                deadline,
                            )
                            .map_err(|_| BrokerError::Cancelled)
                    })
                    .await
                    .map_err(broker_error);
            }
        };
        self.outbox
            .enqueue(FrameV1::new(id, MessageV1::Response(response)), deadline)
    }
}
#[async_trait]
impl LocalAuthStop for RemoteOwner {
    async fn prepare_revocation(&self, cancel_epoch: u64) -> Result<(), BrokerError> {
        match &self.background {
            Some(native) => native.prepare_revocation(cancel_epoch).await,
            None => Ok(()),
        }
    }
    fn revoke_runtime(&self) {
        self.enqueue_revoke();
    }
    async fn stop_local(&self) -> Result<(), BrokerError> {
        match self
            .control(ControlV1::Stop, Instant::now() + REQUEST_BUDGET)
            .await
        {
            Ok(ControlAckV1::Done) => Ok(()),
            _ => Err(BrokerError::RecoveryRequired),
        }
    }
}

pub struct PrivateRuntimeAuthClient {
    outbox: Arc<Outbox>,
    pending: Arc<Pending<AuthResponseV1>>,
    stamp: Mutex<Option<ScopeStamp>>,
    send_gate: Mutex<()>,
    pub(super) pending_login: Mutex<Option<u64>>,
    child: Arc<ChildAdmission>,
}
impl Drop for PrivateRuntimeAuthClient {
    fn drop(&mut self) {
        self.child.close();
        self.outbox.close();
    }
}
impl PrivateRuntimeAuthClient {
    pub async fn owner_request(
        &self,
        request: crate::host::HostRequestV1,
    ) -> Result<crate::host::HostResponseV1, PrivateError> {
        match self
            .request(
                AuthRequestV1::Owner { request },
                Instant::now() + REQUEST_BUDGET,
            )
            .await?
        {
            AuthResponseV1::Owner { response } => Ok(response),
            _ => Err(PrivateError::Protocol),
        }
    }
    pub async fn background(
        &self,
        action: BackgroundAction,
    ) -> Result<AuthResponseV1, PrivateError> {
        let deadline = Instant::now() + REQUEST_BUDGET;
        let stamp = self.stamp(deadline).await?;
        self.request(
            AuthRequestV1::BackgroundCredential { stamp, action },
            deadline,
        )
        .await
    }
    pub fn new<S>(stream: S, child: Arc<ChildAdmission>, stop: Arc<dyn LocalAuthStop>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (outbox, mut incoming) = connect(stream);
        let pending = Arc::new(Pending::default());
        let client_box = outbox.clone();
        let client_pending = pending.clone();
        let client_child = child.clone();
        let mut cancel = outbox.cancellation();
        tokio::spawn(async move {
            let mut controls = tokio::task::JoinSet::new();
            let mut expiry = tokio::time::interval(Duration::from_millis(10));
            loop {
                let (frame, deadline) = tokio::select! { biased;
                    _ = closed(&mut cancel) => break,
                    _ = expiry.tick() => { client_child.expire(); continue; },
                    Some(_) = controls.join_next(), if !controls.is_empty() => continue,
                    frame = incoming.recv() => match frame { Some(frame) => frame, None => break },
                };
                if Instant::now() >= deadline {
                    break;
                }
                match frame.message {
                    MessageV1::Response(response) => {
                        if let AuthResponseV1::Access { stamp, access } = &response {
                            if *stamp != ScopeStamp::from_access(access)
                                || client_child.check(&scope(access)).is_err()
                            {
                                break;
                            }
                        }
                        if client_pending.finish(frame.id, response).is_err() {
                            break;
                        }
                    }
                    MessageV1::Control(control) => {
                        let ack = match control {
                            ControlV1::Prepare { incarnation } => {
                                if controls.len() >= MAX_PENDING {
                                    break;
                                }
                                let child = client_child.clone();
                                let outbox = client_box.clone();
                                controls.spawn(async move {
                                    let ack =
                                        match child.prepare(frame.id, &incarnation, deadline).await
                                        {
                                            Ok(lease) => ControlAckV1::Prepared { lease },
                                            Err(error) => ControlAckV1::Error { error },
                                        };
                                    let _ = outbox.enqueue(
                                        FrameV1::new(frame.id, MessageV1::Ack(ack)),
                                        deadline,
                                    );
                                });
                                continue;
                            }
                            ControlV1::CommitAdmission { lease, scope } => client_child
                                .commit(&lease, &scope)
                                .map(|()| ControlAckV1::Committed),
                            ControlV1::ValidateScope { lease, scope } => client_child
                                .validate_held_scope(&lease, &scope)
                                .map(|()| ControlAckV1::Done),
                            ControlV1::Grant {
                                lease,
                                scope: granted,
                                response,
                            } => {
                                if let Some((_, AuthResponseV1::Access { stamp, access })) =
                                    &*response
                                {
                                    if *stamp != ScopeStamp::from_access(access)
                                        || scope(access) != granted
                                    {
                                        break;
                                    }
                                } else if response.is_some() {
                                    break;
                                }
                                if client_child.grant(&lease, &granted).is_err() {
                                    break;
                                }
                                if let Some((reply_to, response)) = *response {
                                    if client_pending.finish(reply_to, response).is_err() {
                                        break;
                                    }
                                }
                                continue;
                            }
                            ControlV1::Abort { lease } => {
                                client_child.abort(&lease);
                                continue;
                            }
                            ControlV1::Revoke => {
                                client_child.revoke();
                                continue;
                            }
                            ControlV1::CheckScope { scope } => {
                                client_child.check(&scope).map(|()| ControlAckV1::Done)
                            }
                            ControlV1::CleanupSourceSnapshot { lease, scope } => client_child
                                .cleanup_snapshot_for(&lease, scope.as_ref())
                                .map(|snapshot| ControlAckV1::CleanupSnapshot { snapshot }),
                            ControlV1::CompleteCleanup {
                                lease,
                                snapshot,
                                scope,
                            } => client_child
                                .complete_cleanup(&lease, &snapshot, &scope)
                                .map(|()| ControlAckV1::Committed),
                            ControlV1::CompleteLogout { lease, receipt } => client_child
                                .complete_logout(&lease, &receipt)
                                .map(|()| ControlAckV1::Done),
                            ControlV1::Stop => {
                                if controls.len() >= MAX_PENDING {
                                    break;
                                }
                                let stop = stop.clone();
                                let outbox = client_box.clone();
                                controls.spawn(async move {
                                    let ack = match timeout_at(deadline, stop.stop_local()).await {
                                        Ok(Ok(())) => ControlAckV1::Done,
                                        _ => ControlAckV1::Error {
                                            error: PrivateError::RecoveryRequired,
                                        },
                                    };
                                    let _ = outbox.enqueue(
                                        FrameV1::new(frame.id, MessageV1::Ack(ack)),
                                        deadline,
                                    );
                                });
                                continue;
                            }
                        }
                        .unwrap_or_else(|error| ControlAckV1::Error { error });
                        if client_box
                            .enqueue(FrameV1::new(frame.id, MessageV1::Ack(ack)), deadline)
                            .is_err()
                        {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            client_child.close();
            client_box.close();
            client_pending.clear();
            controls.abort_all();
            // Physical stop is independent of held writer guards and is polled
            // even when the peer disappeared before an explicit Stop command.
            let _ = timeout_at(Instant::now() + REQUEST_BUDGET, stop.stop_local()).await;
            while controls.join_next().await.is_some() {}
        });
        Self {
            outbox,
            pending,
            stamp: Mutex::new(None),
            send_gate: Mutex::new(()),
            pending_login: Mutex::new(None),
            child,
        }
    }
    pub(super) async fn request(
        &self,
        request: AuthRequestV1,
        deadline: Instant,
    ) -> Result<AuthResponseV1, PrivateError> {
        let mut lifetime = RequestLifetime {
            outbox: self.outbox.clone(),
            complete: false,
        };
        let (receiver, login_id) = {
            let _send = self.send_gate.lock().map_err(|_| PrivateError::Closed)?;
            let id = self.outbox.id()?;
            let receiver = self.pending.insert(id)?;
            let login_id = if matches!(request, AuthRequestV1::Login { .. }) {
                let mut pending = self
                    .pending_login
                    .lock()
                    .map_err(|_| PrivateError::Closed)?;
                if pending.is_some() {
                    return Err(PrivateError::Cancelled);
                }
                *pending = Some(id);
                Some(id)
            } else {
                None
            };
            self.outbox
                .enqueue(FrameV1::new(id, MessageV1::Request(request)), deadline)?;
            (receiver, login_id)
        };
        let _association = ClientLoginAssociation {
            pending: &self.pending_login,
            id: login_id,
        };
        let mut cancel = self.outbox.cancellation();
        let response = tokio::select! { biased;
            _ = closed(&mut cancel) => Err(PrivateError::Closed),
            result = timeout_at(deadline, receiver) => result.map_err(|_| PrivateError::Timeout)?.map_err(|_| PrivateError::Closed),
        }?;
        lifetime.complete = true;
        match response {
            AuthResponseV1::Error { error } => Err(error),
            response => {
                if let AuthResponseV1::State { stamp, .. } | AuthResponseV1::Access { stamp, .. } =
                    &response
                {
                    *self.stamp.lock().map_err(|_| PrivateError::Closed)? = Some(stamp.clone());
                }
                Ok(response)
            }
        }
    }
    async fn stamp(&self, deadline: Instant) -> Result<Option<ScopeStamp>, PrivateError> {
        let current = self.stamp.lock().map_err(|_| PrivateError::Closed)?.clone();
        if current.is_some() {
            return Ok(current);
        }
        self.request(AuthRequestV1::State, deadline).await?;
        Ok(self.stamp.lock().map_err(|_| PrivateError::Closed)?.clone())
    }
}
#[async_trait]
impl nelomai_client_core::RuntimeStartPreflight for PrivateRuntimeAuthClient {
    async fn before_tunnel_start(&self) -> Result<(), CoreError> {
        match self
            .owner_request(crate::host::HostRequestV1::BeforeTunnelStart)
            .await
            .map_err(core_error)?
        {
            crate::host::HostResponseV1::Done => Ok(()),
            _ => Err(core_error(PrivateError::Protocol)),
        }
    }
    fn check_start_barrier(&self) -> Result<(), CoreError> {
        // Called under the core writer gate: no IPC or recovery is permitted.
        let stamp = self
            .stamp
            .lock()
            .map_err(|_| CoreError::AuthRecoveryRequired)?;
        let scope = stamp
            .as_ref()
            .ok_or(CoreError::AuthRecoveryRequired)?
            .runtime_scope()
            .map_err(|_| CoreError::AuthRecoveryRequired)?;
        self.child.check(&scope).map_err(core_error)
    }
}

#[async_trait]
impl RuntimeAuthProvider for PrivateRuntimeAuthClient {
    async fn state(&self) -> Result<RuntimeAuthState, CoreError> {
        match self
            .request(AuthRequestV1::State, Instant::now() + REQUEST_BUDGET)
            .await
            .map_err(core_error)?
        {
            AuthResponseV1::State { state, .. } => Ok(state),
            _ => Err(core_error(PrivateError::Protocol)),
        }
    }
    async fn login(&self, request: RuntimeLogin) -> Result<AccessSnapshot, CoreError> {
        let deadline = Instant::now() + REQUEST_BUDGET;
        let stamp = self.stamp(deadline).await.map_err(core_error)?;
        match self
            .request(AuthRequestV1::Login { stamp, request }, deadline)
            .await
            .map_err(core_error)?
        {
            AuthResponseV1::Access { access, .. } => {
                self.child.check(&scope(&access)).map_err(core_error)?;
                Ok(access)
            }
            _ => Err(core_error(PrivateError::Protocol)),
        }
    }
    async fn access(&self, stale: Option<&AccessSnapshot>) -> Result<AccessSnapshot, CoreError> {
        let deadline = Instant::now() + REQUEST_BUDGET;
        let stamp = self.stamp(deadline).await.map_err(core_error)?;
        match self
            .request(
                AuthRequestV1::AccessToken {
                    stamp,
                    stale: stale.cloned(),
                },
                deadline,
            )
            .await
            .map_err(core_error)?
        {
            AuthResponseV1::Access { access, .. } => {
                self.child.check(&scope(&access)).map_err(core_error)?;
                Ok(access)
            }
            _ => Err(core_error(PrivateError::Protocol)),
        }
    }
    async fn logout(&self) -> Result<(), CoreError> {
        let deadline = Instant::now() + REQUEST_BUDGET;
        let stamp = self.stamp(deadline).await.map_err(core_error)?;
        let cancel_login_request = *self
            .pending_login
            .lock()
            .map_err(|_| core_error(PrivateError::Closed))?;
        match self
            .request(
                AuthRequestV1::Logout {
                    stamp,
                    cancel_login_request,
                },
                deadline,
            )
            .await
            .map_err(core_error)?
        {
            AuthResponseV1::Done => Ok(()),
            _ => Err(core_error(PrivateError::Protocol)),
        }
    }
}
