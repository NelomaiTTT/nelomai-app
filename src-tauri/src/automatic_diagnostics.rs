use nelomai_client_api::DiagnosticUploadRequest;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;
use uuid::Uuid;

const STATE_FILE: &str = "state.json";
const PENDING_DIRECTORY: &str = "pending";
const SENT_DIRECTORY: &str = "sent";
const REPORT_SUFFIX: &str = ".json";
const CHECKPOINT_SECONDS: i64 = 6 * 60 * 60;
const SUCCESS_UPLOAD_SPACING_SECONDS: i64 = 65;
const MAX_SENT_REPORTS: usize = 3;
const MAX_REPORT_BYTES: usize = 512 * 1024;
const RETRY_DELAYS_SECONDS: [i64; 4] = [5 * 60, 30 * 60, 2 * 60 * 60, 6 * 60 * 60];

pub(crate) struct DesktopAutomaticDiagnostics {
    directory: PathBuf,
    state: Mutex<AutomaticState>,
    upload_in_progress: Arc<AtomicBool>,
    startup_warning: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AutomaticInterval {
    pub session_id: String,
    pub started_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AutomaticObservation {
    pub seal_pending: bool,
    pub interval_started: Option<AutomaticInterval>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct PendingSeal {
    pub report_id: String,
    pub trigger: String,
    pub session_id: String,
    pub device_id: String,
    pub sequence: u64,
    pub started_at: i64,
    pub ended_at: i64,
    pub tunnel_running: bool,
    #[serde(default)]
    pub connection_id: Option<String>,
}

pub(crate) struct UploadCandidate {
    pub name: String,
    pub report: DiagnosticUploadRequest,
    _lease: UploadLease,
}

struct UploadLease {
    upload_in_progress: Arc<AtomicBool>,
}

impl Drop for UploadLease {
    fn drop(&mut self) {
        self.upload_in_progress.store(false, Ordering::Release);
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AutomaticSession {
    connection_id: String,
    session_id: String,
    device_id: String,
    sequence: u64,
    interval_started_at: i64,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct AutomaticState {
    current_device_id: Option<String>,
    session: Option<AutomaticSession>,
    pending_seal: Option<PendingSeal>,
    retry_attempt: usize,
    next_upload_at: i64,
    last_attempted_report: Option<String>,
}

impl DesktopAutomaticDiagnostics {
    pub(crate) fn new(directory: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(directory.join(PENDING_DIRECTORY))?;
        fs::create_dir_all(directory.join(SENT_DIRECTORY))?;
        restrict_directory_permissions(&directory)?;
        let state = load_state_resilient(&directory, &directory.join(STATE_FILE))?;
        let mut diagnostics = Self {
            directory,
            state: Mutex::new(state),
            upload_in_progress: Arc::new(AtomicBool::new(false)),
            startup_warning: None,
        };
        diagnostics.startup_warning = diagnostics
            .prune_sent()
            .err()
            .map(|error| error.kind().to_string());
        Ok(diagnostics)
    }

    pub(crate) fn startup_warning(&self) -> Option<&str> {
        self.startup_warning.as_deref()
    }

    pub(crate) fn set_current_device(&self, device_id: &str) -> io::Result<()> {
        validate_scope(device_id)?;
        let mut state = self.lock_state()?;
        if state.current_device_id.as_deref() != Some(device_id) {
            state.current_device_id = Some(device_id.to_string());
            self.save_state(&state)?;
        }
        Ok(())
    }

    pub(crate) fn clear_current_device(&self) -> io::Result<()> {
        let mut state = self.lock_state()?;
        if state.current_device_id.take().is_some() {
            self.save_state(&state)?;
        }
        Ok(())
    }

    pub(crate) fn observe(
        &self,
        session_id: Option<&str>,
        tunnel_may_be_running: bool,
        now: i64,
    ) -> io::Result<AutomaticObservation> {
        let mut state = self.lock_state()?;
        if state.pending_seal.is_some() {
            return Ok(AutomaticObservation {
                seal_pending: true,
                interval_started: None,
            });
        }

        let mut interval_started = None;
        match (state.session.as_ref(), session_id) {
            (None, Some(session_id)) => {
                let Some(device_id) = state.current_device_id.clone() else {
                    return Ok(AutomaticObservation::default());
                };
                let session = AutomaticSession {
                    connection_id: session_id.to_string(),
                    session_id: Uuid::new_v4().to_string(),
                    device_id,
                    sequence: 0,
                    interval_started_at: now,
                };
                interval_started = Some(AutomaticInterval {
                    session_id: session.session_id.clone(),
                    started_at: session.interval_started_at,
                });
                state.session = Some(session);
                self.save_state(&state)?;
            }
            (Some(session), Some(session_id)) if session.connection_id != session_id => {
                state.pending_seal = Some(seal(session, "tunnel_stopped", false, now));
                self.save_state(&state)?;
                return Ok(AutomaticObservation {
                    seal_pending: true,
                    interval_started: None,
                });
            }
            (Some(session), None) if !tunnel_may_be_running => {
                state.pending_seal = Some(seal(session, "tunnel_stopped", false, now));
                self.save_state(&state)?;
                return Ok(AutomaticObservation {
                    seal_pending: true,
                    interval_started: None,
                });
            }
            (Some(session), Some(_))
                if now.saturating_sub(session.interval_started_at) >= CHECKPOINT_SECONDS =>
            {
                state.pending_seal = Some(seal(session, "six_hour_checkpoint", true, now));
                self.save_state(&state)?;
                return Ok(AutomaticObservation {
                    seal_pending: true,
                    interval_started: None,
                });
            }
            _ => {}
        }
        Ok(AutomaticObservation {
            seal_pending: false,
            interval_started,
        })
    }

    pub(crate) fn pending_seal(&self) -> io::Result<Option<PendingSeal>> {
        Ok(self.lock_state()?.pending_seal.clone())
    }

    pub(crate) fn materialize(
        &self,
        seal: &PendingSeal,
        report: &DiagnosticUploadRequest,
    ) -> io::Result<()> {
        if report.report_id.as_deref() != Some(seal.report_id.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "automatic diagnostics report id mismatch",
            ));
        }
        let name = report_name(seal)?;
        let destination = self.pending_directory().join(&name);
        if !destination.is_file() {
            write_json_atomically(&destination, report, MAX_REPORT_BYTES)?;
        }

        let mut state = self.lock_state()?;
        if state.pending_seal.as_ref() != Some(seal) {
            return Err(io::Error::other(
                "automatic diagnostics seal changed while materializing",
            ));
        }
        if seal.tunnel_running {
            let session = state
                .session
                .as_mut()
                .ok_or_else(|| io::Error::other("automatic diagnostics session is unavailable"))?;
            session.sequence = seal.sequence;
            session.interval_started_at = seal.ended_at;
        } else {
            state.session = None;
        }
        state.pending_seal = None;
        self.save_state(&state)
    }

    pub(crate) fn upload_candidate(&self, now: i64) -> io::Result<Option<UploadCandidate>> {
        self.begin_upload_candidate(now, false)
    }

    pub(crate) fn upload_latest_candidate(&self, now: i64) -> io::Result<Option<UploadCandidate>> {
        self.begin_upload_candidate(now, true)
    }

    fn begin_upload_candidate(
        &self,
        now: i64,
        latest: bool,
    ) -> io::Result<Option<UploadCandidate>> {
        if self.upload_in_progress.swap(true, Ordering::AcqRel) {
            return Ok(None);
        }
        match self.upload_candidate_inner(now, latest) {
            Ok(Some((name, report))) => Ok(Some(UploadCandidate {
                name,
                report,
                _lease: UploadLease {
                    upload_in_progress: self.upload_in_progress.clone(),
                },
            })),
            Ok(None) => {
                self.upload_in_progress.store(false, Ordering::Release);
                Ok(None)
            }
            Err(error) => {
                self.upload_in_progress.store(false, Ordering::Release);
                Err(error)
            }
        }
    }

    fn upload_candidate_inner(
        &self,
        now: i64,
        latest: bool,
    ) -> io::Result<Option<(String, DiagnosticUploadRequest)>> {
        let mut state = self.lock_state()?;
        if !latest && now < state.next_upload_at {
            return Ok(None);
        }
        let Some(device_id) = state.current_device_id.as_deref() else {
            return Ok(None);
        };
        let reports = self.pending_reports_for(device_id)?;
        let name = if latest {
            reports.last().cloned()
        } else {
            next_report_name(&reports, state.last_attempted_report.as_deref())
        };
        let Some(name) = name else {
            state.retry_attempt = 0;
            state.next_upload_at = 0;
            state.last_attempted_report = None;
            self.save_state(&state)?;
            return Ok(None);
        };
        state.last_attempted_report = Some(name.clone());
        self.save_state(&state)?;
        let report = read_report(&self.pending_directory().join(&name))?;
        Ok(Some((name, report)))
    }

    pub(crate) fn upload_succeeded(&self, candidate: &UploadCandidate, now: i64) -> io::Result<()> {
        (|| {
            let source = self.pending_directory().join(&candidate.name);
            let destination = self.sent_directory().join(&candidate.name);
            fs::rename(source, destination)?;
            sync_directory(&self.pending_directory())?;
            sync_directory(&self.sent_directory())?;

            let mut state = self.lock_state()?;
            let more_pending = state
                .current_device_id
                .as_deref()
                .map(|device_id| self.pending_reports_for(device_id))
                .transpose()?
                .is_some_and(|reports| !reports.is_empty());
            state.retry_attempt = 0;
            state.next_upload_at = if more_pending {
                now.saturating_add(SUCCESS_UPLOAD_SPACING_SECONDS)
            } else {
                0
            };
            self.save_state(&state)?;
            drop(state);
            let _ = self.prune_sent();
            Ok(())
        })()
    }

    pub(crate) fn upload_failed(&self, now: i64) -> io::Result<i64> {
        (|| {
            let mut state = self.lock_state()?;
            let delay =
                RETRY_DELAYS_SECONDS[state.retry_attempt.min(RETRY_DELAYS_SECONDS.len() - 1)];
            state.retry_attempt = state
                .retry_attempt
                .saturating_add(1)
                .min(RETRY_DELAYS_SECONDS.len());
            state.next_upload_at = now.saturating_add(delay);
            self.save_state(&state)?;
            Ok(delay)
        })()
    }

    fn lock_state(&self) -> io::Result<std::sync::MutexGuard<'_, AutomaticState>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("automatic diagnostics lock poisoned"))
    }

    fn save_state(&self, state: &AutomaticState) -> io::Result<()> {
        write_json_atomically(&self.directory.join(STATE_FILE), state, 64 * 1024)
    }

    fn pending_directory(&self) -> PathBuf {
        self.directory.join(PENDING_DIRECTORY)
    }

    fn sent_directory(&self) -> PathBuf {
        self.directory.join(SENT_DIRECTORY)
    }

    fn pending_reports_for(&self, device_id: &str) -> io::Result<Vec<String>> {
        let mut names = fs::read_dir(self.pending_directory())?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| report_scope(name) == Some(device_id))
            .collect::<Vec<_>>();
        names.sort();
        Ok(names)
    }

    fn prune_sent(&self) -> io::Result<()> {
        let mut reports = fs::read_dir(self.sent_directory())?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect::<Vec<_>>();
        reports.sort();
        let remove_count = reports.len().saturating_sub(MAX_SENT_REPORTS);
        for path in reports.into_iter().take(remove_count) {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

fn seal(session: &AutomaticSession, trigger: &str, tunnel_running: bool, now: i64) -> PendingSeal {
    PendingSeal {
        report_id: Uuid::new_v4().to_string(),
        trigger: trigger.to_string(),
        session_id: session.session_id.clone(),
        device_id: session.device_id.clone(),
        sequence: session.sequence.saturating_add(1),
        started_at: session.interval_started_at,
        ended_at: now.max(session.interval_started_at),
        tunnel_running,
        connection_id: Some(session.connection_id.clone()),
    }
}

fn report_name(seal: &PendingSeal) -> io::Result<String> {
    validate_scope(&seal.device_id)?;
    let report_id = Uuid::parse_str(&seal.report_id)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    Ok(format!(
        "{:020}.{}.{}{}",
        seal.ended_at.max(0),
        seal.device_id,
        report_id,
        REPORT_SUFFIX
    ))
}

fn report_scope(name: &str) -> Option<&str> {
    let mut parts = name.split('.');
    parts.next()?;
    let scope = parts.next()?;
    let report_id = parts.next()?;
    let suffix = parts.next()?;
    (suffix == "json" && parts.next().is_none() && Uuid::parse_str(report_id).is_ok())
        .then_some(scope)
}

fn next_report_name(reports: &[String], last_attempted: Option<&str>) -> Option<String> {
    last_attempted
        .and_then(|last| reports.iter().find(|name| name.as_str() > last))
        .or_else(|| reports.first())
        .cloned()
}

fn validate_scope(scope: &str) -> io::Result<()> {
    if !scope.is_empty()
        && scope.len() <= 128
        && scope
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid automatic diagnostics device scope",
        ))
    }
}

fn load_state(path: &Path) -> io::Result<AutomaticState> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(AutomaticState::default()),
        Err(error) => Err(error),
    }
}

fn load_state_resilient(directory: &Path, path: &Path) -> io::Result<AutomaticState> {
    match load_state(path) {
        Ok(state) => Ok(state),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            let quarantine = directory.join(format!(
                "state.corrupt-{}-{}.json",
                unix_now(),
                Uuid::new_v4()
            ));
            fs::rename(path, quarantine)?;
            sync_directory(directory)?;
            Ok(AutomaticState::default())
        }
        Err(error) => Err(error),
    }
}

fn read_report(path: &Path) -> io::Result<DiagnosticUploadRequest> {
    let bytes = fs::read(path)?;
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "automatic diagnostics report is too large",
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn write_json_atomically(path: &Path, value: &impl Serialize, maximum: usize) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent directory"))?;
    fs::create_dir_all(parent)?;
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "automatic diagnostics payload is too large",
        ));
    }
    let mut temporary = NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(&bytes)?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_directory(parent)?;
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(seal: &PendingSeal) -> DiagnosticUploadRequest {
        DiagnosticUploadRequest {
            report_id: Some(seal.report_id.clone()),
            trigger: seal.trigger.clone(),
            tunnel_session_id: Some(seal.session_id.clone()),
            sequence: Some(seal.sequence),
            interval_started_at_unix: Some(seal.started_at),
            interval_ended_at_unix: Some(seal.ended_at),
            tunnel_running: Some(seal.tunnel_running),
            connection_lease_id: seal.connection_id.clone(),
            generated_at_unix: seal.ended_at,
            app_version: "test".to_string(),
            platform_version: None,
            architecture: "test".to_string(),
            application_log: "test".to_string(),
            helper_log: None,
            network_incidents: None,
            resource_usage: None,
        }
    }

    #[test]
    fn queues_stop_report_and_keeps_it_pending_until_success() {
        let directory = tempfile::tempdir().unwrap();
        let queue = DesktopAutomaticDiagnostics::new(directory.path().to_path_buf()).unwrap();
        queue.set_current_device("device-1").unwrap();
        queue.observe(Some("session-1"), true, 10).unwrap();
        assert!(queue.observe(None, false, 20).unwrap().seal_pending);
        let seal = queue.pending_seal().unwrap().unwrap();
        queue.materialize(&seal, &report(&seal)).unwrap();

        let first = queue.upload_candidate(20).unwrap().unwrap();
        queue.upload_failed(20).unwrap();
        assert!(queue.pending_directory().join(&first.name).is_file());
        drop(first);
        assert!(queue.upload_candidate(21).unwrap().is_none());

        let retry = queue
            .upload_candidate(20 + RETRY_DELAYS_SECONDS[0])
            .unwrap()
            .unwrap();
        queue
            .upload_succeeded(&retry, 20 + RETRY_DELAYS_SECONDS[0])
            .unwrap();
        assert!(!queue.pending_directory().join(&retry.name).exists());
        assert!(queue.sent_directory().join(&retry.name).is_file());
    }

    #[test]
    fn completed_stop_does_not_create_a_duplicate_but_restart_starts_a_new_interval() {
        let directory = tempfile::tempdir().unwrap();
        let queue = DesktopAutomaticDiagnostics::new(directory.path().to_path_buf()).unwrap();
        queue.set_current_device("device-1").unwrap();
        queue.observe(Some("lease-1"), true, 10).unwrap();
        queue.observe(None, false, 20).unwrap();
        let first = queue.pending_seal().unwrap().unwrap();
        queue.materialize(&first, &report(&first)).unwrap();

        let duplicate_stop = queue.observe(None, false, 21).unwrap();
        assert!(!duplicate_stop.seal_pending);
        assert!(duplicate_stop.interval_started.is_none());
        assert!(queue.pending_seal().unwrap().is_none());

        let restarted = queue.observe(Some("lease-1"), true, 30).unwrap();
        assert!(restarted.interval_started.is_some());
        assert!(queue.observe(None, false, 40).unwrap().seal_pending);
        let second = queue.pending_seal().unwrap().unwrap();
        assert_ne!(first.session_id, second.session_id);
    }

    #[test]
    fn seals_six_hour_intervals_without_ending_session() {
        let directory = tempfile::tempdir().unwrap();
        let queue = DesktopAutomaticDiagnostics::new(directory.path().to_path_buf()).unwrap();
        queue.set_current_device("device-1").unwrap();
        queue.observe(Some("session-1"), true, 10).unwrap();

        assert!(
            queue
                .observe(Some("session-1"), true, 10 + CHECKPOINT_SECONDS)
                .unwrap()
                .seal_pending
        );
        let first = queue.pending_seal().unwrap().unwrap();
        assert_eq!(first.trigger, "six_hour_checkpoint");
        assert!(first.tunnel_running);
        queue.materialize(&first, &report(&first)).unwrap();

        assert!(
            !queue
                .observe(Some("session-1"), true, 10 + CHECKPOINT_SECONDS + 1)
                .unwrap()
                .seal_pending
        );
    }

    #[test]
    fn corrupt_pending_report_does_not_starve_the_next_report() {
        let directory = tempfile::tempdir().unwrap();
        let queue = DesktopAutomaticDiagnostics::new(directory.path().to_path_buf()).unwrap();
        queue.set_current_device("device-1").unwrap();

        queue.observe(Some("connection-1"), true, 10).unwrap();
        queue.observe(None, false, 20).unwrap();
        let first = queue.pending_seal().unwrap().unwrap();
        queue.materialize(&first, &report(&first)).unwrap();
        queue.observe(Some("connection-2"), true, 30).unwrap();
        queue.observe(None, false, 40).unwrap();
        let second = queue.pending_seal().unwrap().unwrap();
        queue.materialize(&second, &report(&second)).unwrap();

        let first_path = queue.pending_directory().join(report_name(&first).unwrap());
        fs::write(first_path, b"not-json").unwrap();
        assert!(queue.upload_candidate(40).is_err());
        queue.upload_failed(40).unwrap();

        let candidate = queue
            .upload_candidate(40 + RETRY_DELAYS_SECONDS[0])
            .unwrap()
            .unwrap();
        assert_eq!(candidate.report.report_id, Some(second.report_id));
    }

    #[test]
    fn multiple_corrupt_reports_do_not_starve_a_later_valid_report() {
        let directory = tempfile::tempdir().unwrap();
        let queue = DesktopAutomaticDiagnostics::new(directory.path().to_path_buf()).unwrap();
        queue.set_current_device("device-1").unwrap();

        let mut seals = Vec::new();
        for index in 0..3 {
            let started_at = 10 + index * 20;
            queue
                .observe(Some(&format!("connection-{index}")), true, started_at)
                .unwrap();
            queue.observe(None, false, started_at + 10).unwrap();
            let seal = queue.pending_seal().unwrap().unwrap();
            queue.materialize(&seal, &report(&seal)).unwrap();
            seals.push(seal);
        }
        for seal in &seals[..2] {
            fs::write(
                queue.pending_directory().join(report_name(seal).unwrap()),
                b"not-json",
            )
            .unwrap();
        }

        assert!(queue.upload_candidate(60).is_err());
        queue.upload_failed(60).unwrap();
        let second_attempt = 60 + RETRY_DELAYS_SECONDS[0];
        assert!(queue.upload_candidate(second_attempt).is_err());
        queue.upload_failed(second_attempt).unwrap();
        let third_attempt = second_attempt + RETRY_DELAYS_SECONDS[1];
        let candidate = queue.upload_candidate(third_attempt).unwrap().unwrap();

        assert_eq!(candidate.report.report_id, Some(seals[2].report_id.clone()));
    }

    #[test]
    fn logout_candidate_uses_the_latest_report_despite_retry_backoff() {
        let directory = tempfile::tempdir().unwrap();
        let queue = DesktopAutomaticDiagnostics::new(directory.path().to_path_buf()).unwrap();
        queue.set_current_device("device-1").unwrap();

        queue.observe(Some("connection-1"), true, 10).unwrap();
        queue.observe(None, false, 20).unwrap();
        let first = queue.pending_seal().unwrap().unwrap();
        queue.materialize(&first, &report(&first)).unwrap();
        queue.observe(Some("connection-2"), true, 30).unwrap();
        queue.observe(None, false, 40).unwrap();
        let latest = queue.pending_seal().unwrap().unwrap();
        queue.materialize(&latest, &report(&latest)).unwrap();

        let _ = queue.upload_candidate(40).unwrap().unwrap();
        queue.upload_failed(40).unwrap();
        assert!(queue.upload_candidate(41).unwrap().is_none());
        let candidate = queue.upload_latest_candidate(41).unwrap().unwrap();

        assert_eq!(candidate.report.report_id, Some(latest.report_id));
    }

    #[test]
    fn dropping_an_upload_candidate_releases_the_upload_gate() {
        let directory = tempfile::tempdir().unwrap();
        let queue = DesktopAutomaticDiagnostics::new(directory.path().to_path_buf()).unwrap();
        queue.set_current_device("device-1").unwrap();
        queue.observe(Some("connection-1"), true, 10).unwrap();
        queue.observe(None, false, 20).unwrap();
        let seal = queue.pending_seal().unwrap().unwrap();
        queue.materialize(&seal, &report(&seal)).unwrap();

        let candidate = queue.upload_candidate(20).unwrap().unwrap();
        assert!(queue.upload_candidate(20).unwrap().is_none());
        drop(candidate);

        assert!(queue.upload_candidate(20).unwrap().is_some());
    }

    #[test]
    fn corrupt_state_is_quarantined_without_touching_pending_reports() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join(PENDING_DIRECTORY)).unwrap();
        fs::create_dir_all(directory.path().join(SENT_DIRECTORY)).unwrap();
        fs::write(directory.path().join(STATE_FILE), b"not-json").unwrap();
        fs::write(
            directory
                .path()
                .join(PENDING_DIRECTORY)
                .join("keep.pending"),
            b"pending",
        )
        .unwrap();

        let _queue = DesktopAutomaticDiagnostics::new(directory.path().to_path_buf()).unwrap();

        assert!(directory
            .path()
            .join(PENDING_DIRECTORY)
            .join("keep.pending")
            .is_file());
        assert!(fs::read_dir(directory.path()).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("state.corrupt-")));
    }

    #[test]
    fn startup_prunes_only_confirmed_history_and_keeps_all_pending_files() {
        let directory = tempfile::tempdir().unwrap();
        let pending = directory.path().join(PENDING_DIRECTORY);
        let sent = directory.path().join(SENT_DIRECTORY);
        fs::create_dir_all(&pending).unwrap();
        fs::create_dir_all(&sent).unwrap();
        for index in 0..5 {
            fs::write(pending.join(format!("{index}.json")), b"pending").unwrap();
            fs::write(sent.join(format!("{index}.json")), b"sent").unwrap();
        }

        let _queue = DesktopAutomaticDiagnostics::new(directory.path().to_path_buf()).unwrap();

        assert_eq!(fs::read_dir(pending).unwrap().count(), 5);
        assert_eq!(fs::read_dir(sent).unwrap().count(), MAX_SENT_REPORTS);
    }
}
