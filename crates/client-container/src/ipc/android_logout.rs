//! A latest Android runtime can be replaced before its logout reaches the
//! broker. Keep only the original, nonsecret scope across that replacement.
use super::*;
use crate::{
    host::{HostRequestV1, HostResponseV1},
    selection::{atomic_nonsecret_write, read_optional_bounded},
};
use std::{fs, io, path::PathBuf};
use tokio::sync::{Mutex, MutexGuard};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogoutIntent {
    scope: ScopeStamp,
    confirmed: bool,
}

pub(super) struct AndroidLogout {
    path: PathBuf,
    gate: Mutex<()>,
    clear_quick_plan: Box<dyn Fn() -> Result<(), PrivateError> + Send + Sync>,
}

impl AndroidLogout {
    fn load(&self) -> Result<Option<LogoutIntent>, PrivateError> {
        read_optional_bounded(&self.path, MAX_FRAME_BYTES)
            .map_err(|_| PrivateError::RecoveryRequired)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| PrivateError::RecoveryRequired))
            .transpose()
    }

    fn save(&self, intent: &LogoutIntent) -> Result<(), PrivateError> {
        let bytes = serde_json::to_vec(intent).map_err(|_| PrivateError::Protocol)?;
        atomic_nonsecret_write(&self.path, &bytes).map_err(|_| PrivateError::RecoveryRequired)
    }

    fn retire(&self) -> Result<(), PrivateError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(PrivateError::RecoveryRequired),
        }
    }

    fn finish(&self, mut intent: LogoutIntent) -> Result<(), PrivateError> {
        if !intent.confirmed {
            intent.confirmed = true;
            self.save(&intent)?;
        }
        (self.clear_quick_plan)()?;
        self.retire()
    }

    pub(super) fn check_login(&self) -> Result<(), PrivateError> {
        // A replacement Login must not overtake confirmed logout cleanup.
        if self.load()?.is_some() {
            return Err(PrivateError::RecoveryRequired);
        }
        Ok(())
    }
}

impl PrivateRuntimeAuthClient {
    pub fn enable_android_logout_recovery(
        &mut self,
        path: PathBuf,
        clear_quick_plan: impl Fn() -> Result<(), PrivateError> + Send + Sync + 'static,
    ) {
        self.android_logout = Some(AndroidLogout {
            path,
            gate: Mutex::new(()),
            clear_quick_plan: Box::new(clear_quick_plan),
        });
    }

    pub(super) async fn logout_android(
        &self,
        recovery: &AndroidLogout,
    ) -> Result<(), PrivateError> {
        let _guard = recovery.gate.lock().await;
        if let Some(source) = recovery.load()? {
            return self
                .replay_android_logout(recovery, source)
                .await?
                .then_some(())
                .ok_or(PrivateError::Cancelled);
        }
        let deadline = Instant::now() + REQUEST_BUDGET;
        let source = self.stamp(deadline).await?.ok_or(PrivateError::Cancelled)?;
        let intent = LogoutIntent {
            scope: source,
            confirmed: false,
        };
        recovery.save(&intent)?;
        self.send_logout(Some(intent.scope.clone()), deadline)
            .await?;
        recovery.finish(intent)
    }

    /// True when the original logout was completed, including owner readiness.
    pub async fn recover_pending_android_logout(&self) -> Result<bool, PrivateError> {
        let Some(recovery) = &self.android_logout else {
            return Ok(false);
        };
        let _guard = recovery.gate.lock().await;
        let Some(source) = recovery.load()? else {
            return Ok(false);
        };
        match self.replay_android_logout(recovery, source).await {
            // The scope or a writer lease can change while this replay is in
            // flight. Re-observe the saved intent on the next readiness pass.
            Err(PrivateError::Cancelled) => Err(PrivateError::RecoveryRequired),
            result => result,
        }
    }

    /// Permit the broker's existing same-account recovery for an unknown
    /// password outcome. Keep replay serialized until that explicit Login
    /// finishes. A rejected Login leaves the original intent intact.
    pub(super) async fn prepare_android_login<'a>(
        &self,
        recovery: &'a AndroidLogout,
    ) -> Result<Option<MutexGuard<'a, ()>>, PrivateError> {
        let guard = recovery.gate.lock().await;
        let Some(intent) = recovery.load()? else {
            return Ok(None);
        };
        match self.replay_android_logout(recovery, intent).await {
            Ok(_) => Ok(None),
            Err(PrivateError::OutcomeUnknown) => Ok(Some(guard)),
            Err(error) => Err(error),
        }
    }

    async fn replay_android_logout(
        &self,
        recovery: &AndroidLogout,
        intent: LogoutIntent,
    ) -> Result<bool, PrivateError> {
        let deadline = Instant::now() + REQUEST_BUDGET;
        let AuthResponseV1::State { stamp, state } =
            self.request(AuthRequestV1::State, deadline).await?
        else {
            return Err(PrivateError::Protocol);
        };

        if stamp != intent.scope && !stamp.follows_logout_of(&intent.scope) {
            recovery.retire()?;
            return Ok(false);
        }

        if state == RuntimeAuthState::AuthenticationOutcomeUnknown {
            return Err(PrivateError::OutcomeUnknown);
        }

        if intent.confirmed {
            if state != RuntimeAuthState::LoggedOut {
                return Err(PrivateError::RecoveryRequired);
            }
            match self.owner_request(HostRequestV1::RuntimeReady).await? {
                HostResponseV1::Done => {}
                _ => return Err(PrivateError::Protocol),
            }
        } else {
            // A signed-out observation alone is not a physical Stop ACK.
            // The existing fenced Logout on LoggedOut repeats local cleanup
            // without making another revocation HTTP request.
            self.send_logout(Some(stamp), Instant::now() + REQUEST_BUDGET)
                .await?;
        }
        recovery.finish(intent)?;
        Ok(true)
    }
}
