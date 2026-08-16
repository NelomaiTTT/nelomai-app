use nelomai_client_tunnel::TunnelMetrics;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::NamedTempFile;
use uuid::Uuid;

const FORMAT_VERSION: u8 = 1;
const MAX_SAMPLES: usize = 60;
const MAX_DETAILED_INCIDENTS: usize = 3;
const MINIMUM_SESSION_AGE_SECONDS: i64 = 10;
const STALL_SECONDS: i64 = 5;
const MINIMUM_CANDIDATE_SENT_BYTES: u64 = 1_024;
const MINIMUM_CANDIDATE_ACTIVE_SAMPLES: u8 = 2;
const CANDIDATE_INACTIVITY_SECONDS: i64 = 10;
const MAXIMUM_LEGACY_ADDITIONAL_INCIDENTS: u64 = 100_000;
const MAX_SNAPSHOT_PAYLOAD_BYTES: usize = 60 * 1024;
const MAX_COMPACTED_SAMPLES_PER_INCIDENT: usize = 12;
const MAX_COMPACTED_ADDITIONAL_INCIDENTS: usize = 64;

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub(crate) struct NetworkIncidentRecorder {
    path: PathBuf,
    detector: Mutex<Detector>,
    archive_gate: Mutex<()>,
    current_device_id: Mutex<Option<String>>,
    startup_warning: Option<String>,
}

pub(crate) struct NetworkIncidentSnapshot {
    pub payload: String,
    incident_ids: Vec<String>,
    open_incident_ids: HashSet<String>,
}

#[derive(Default)]
struct Detector {
    connection_id: Option<String>,
    started_at_unix: i64,
    candidate_started_at_unix: Option<i64>,
    candidate_sent_bytes: u64,
    candidate_active_samples: u8,
    candidate_last_activity_at_unix: Option<i64>,
    open_incident_at_unix: Option<i64>,
    samples: VecDeque<NetworkIncidentSample>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NetworkIncidentArchive {
    version: u8,
    sessions: Vec<NetworkIncidentSession>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compaction: Option<NetworkIncidentCompaction>,
}

impl Default for NetworkIncidentArchive {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            sessions: Vec::new(),
            compaction: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NetworkIncidentCompaction {
    omitted_session_count: u64,
    omitted_incident_count: u64,
    first_omitted_at_unix: Option<i64>,
    last_omitted_at_unix: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NetworkIncidentSession {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    connection_lease_id: String,
    detailed: Vec<NetworkIncident>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    additional: Vec<NetworkIncidentSummary>,
    #[serde(default, skip_serializing_if = "is_zero")]
    additional_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first_additional_at_unix: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_additional_at_unix: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NetworkIncident {
    #[serde(default)]
    id: String,
    kind: String,
    detected_at_unix: i64,
    recovered_at_unix: Option<i64>,
    duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "is_false")]
    open: bool,
    samples: Vec<NetworkIncidentSample>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NetworkIncidentSummary {
    #[serde(default)]
    id: String,
    kind: String,
    detected_at_unix: i64,
    recovered_at_unix: Option<i64>,
    duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "is_false")]
    open: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NetworkIncidentSample {
    observed_at_unix: i64,
    received_bytes: u64,
    sent_bytes: u64,
    received_delta_bytes: u64,
    sent_delta_bytes: u64,
    latest_handshake_epoch_millis: Option<u64>,
    handshake_age_seconds: Option<u64>,
}

impl NetworkIncidentRecorder {
    pub(crate) fn new(directory: &Path) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        let path = directory.join("network-incidents.json");
        let startup_warning = prepare_archive(&path)?;
        Ok(Self {
            path,
            detector: Mutex::new(Detector::default()),
            archive_gate: Mutex::new(()),
            current_device_id: Mutex::new(None),
            startup_warning,
        })
    }

    pub(crate) fn startup_warning(&self) -> Option<&str> {
        self.startup_warning.as_deref()
    }

    pub(crate) fn set_current_device(&self, device_id: &str) -> io::Result<()> {
        if device_id.is_empty() || device_id.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid network incident device scope",
            ));
        }
        *self
            .current_device_id
            .lock()
            .map_err(|_| io::Error::other("network incident device lock poisoned"))? =
            Some(device_id.to_string());
        Ok(())
    }

    pub(crate) fn clear_current_device(&self) -> io::Result<()> {
        *self
            .current_device_id
            .lock()
            .map_err(|_| io::Error::other("network incident device lock poisoned"))? = None;
        Ok(())
    }

    pub(crate) fn current_device_id(&self) -> io::Result<Option<String>> {
        self.current_device_id
            .lock()
            .map(|value| value.clone())
            .map_err(|_| io::Error::other("network incident device lock poisoned"))
    }

    pub(crate) fn reset_detector(&self) -> io::Result<()> {
        *self
            .detector
            .lock()
            .map_err(|_| io::Error::other("network incident detector lock poisoned"))? =
            Detector::default();
        Ok(())
    }

    pub(crate) fn observe(
        &self,
        connection_id: &str,
        sample: &TunnelMetrics,
        previous: Option<&TunnelMetrics>,
        now_unix: i64,
    ) -> io::Result<()> {
        let mut detector = self
            .detector
            .lock()
            .map_err(|_| io::Error::other("network incident detector lock poisoned"))?;
        if detector.connection_id.as_deref() != Some(connection_id) {
            *detector = Detector {
                connection_id: Some(connection_id.to_string()),
                started_at_unix: now_unix,
                ..Detector::default()
            };
        }
        let received_delta = counter_delta(
            previous.map(|value| value.received_bytes),
            sample.received_bytes,
        );
        let sent_delta = counter_delta(previous.map(|value| value.sent_bytes), sample.sent_bytes);
        detector.samples.push_back(NetworkIncidentSample {
            observed_at_unix: now_unix,
            received_bytes: sample.received_bytes,
            sent_bytes: sample.sent_bytes,
            received_delta_bytes: received_delta,
            sent_delta_bytes: sent_delta,
            latest_handshake_epoch_millis: sample.latest_handshake_epoch_millis,
            handshake_age_seconds: sample.latest_handshake_epoch_millis.map(|handshake| {
                (now_unix.max(0) as u64)
                    .saturating_mul(1_000)
                    .saturating_sub(handshake)
                    / 1_000
            }),
        });
        while detector.samples.len() > MAX_SAMPLES {
            detector.samples.pop_front();
        }

        if received_delta > 0 {
            detector.candidate_started_at_unix = None;
            detector.candidate_sent_bytes = 0;
            detector.candidate_active_samples = 0;
            detector.candidate_last_activity_at_unix = None;
            if let Some(detected_at) = detector.open_incident_at_unix.take() {
                drop(detector);
                let result = self.record_recovery(connection_id, detected_at, now_unix);
                if result.is_err() {
                    if let Ok(mut detector) = self.detector.lock() {
                        if detector.connection_id.as_deref() == Some(connection_id)
                            && detector.open_incident_at_unix.is_none()
                        {
                            detector.open_incident_at_unix = Some(detected_at);
                        }
                    }
                }
                return result;
            }
            return Ok(());
        }
        if sent_delta > 0 {
            detector.candidate_started_at_unix.get_or_insert(now_unix);
            detector.candidate_sent_bytes =
                detector.candidate_sent_bytes.saturating_add(sent_delta);
            detector.candidate_active_samples = detector.candidate_active_samples.saturating_add(1);
            detector.candidate_last_activity_at_unix = Some(now_unix);
        } else if detector.open_incident_at_unix.is_none()
            && detector
                .candidate_last_activity_at_unix
                .is_some_and(|last| now_unix.saturating_sub(last) > CANDIDATE_INACTIVITY_SECONDS)
        {
            detector.candidate_started_at_unix = None;
            detector.candidate_sent_bytes = 0;
            detector.candidate_active_samples = 0;
            detector.candidate_last_activity_at_unix = None;
        }
        let Some(candidate_at) = detector.candidate_started_at_unix else {
            return Ok(());
        };
        if detector.open_incident_at_unix.is_some()
            || now_unix.saturating_sub(detector.started_at_unix) < MINIMUM_SESSION_AGE_SECONDS
            || now_unix.saturating_sub(candidate_at) < STALL_SECONDS
            || detector.candidate_sent_bytes < MINIMUM_CANDIDATE_SENT_BYTES
            || detector.candidate_active_samples < MINIMUM_CANDIDATE_ACTIVE_SAMPLES
        {
            return Ok(());
        }
        detector.open_incident_at_unix = Some(now_unix);
        let samples = detector.samples.iter().cloned().collect();
        drop(detector);
        let result = self.record_detection(connection_id, now_unix, samples);
        if result.is_err() {
            if let Ok(mut detector) = self.detector.lock() {
                if detector.connection_id.as_deref() == Some(connection_id)
                    && detector.open_incident_at_unix == Some(now_unix)
                {
                    detector.open_incident_at_unix = None;
                }
            }
        }
        result
    }

    pub(crate) fn snapshot(
        &self,
        connection_id: Option<&str>,
        device_id: Option<&str>,
        started_at_unix: Option<i64>,
        ended_at_unix: Option<i64>,
    ) -> io::Result<Option<NetworkIncidentSnapshot>> {
        let _archive_guard = self.lock_archive()?;
        let archive = read_archive(&self.path)?;
        let mut selected = archive;
        selected.sessions.retain_mut(|session| {
            if connection_id.is_some_and(|value| value != session.connection_lease_id) {
                return false;
            }
            if device_id.is_some_and(|value| session.device_id.as_deref() != Some(value)) {
                return false;
            }
            session.detailed.retain(|incident| {
                incident.open
                    || timestamp_in_interval(
                        incident.detected_at_unix,
                        started_at_unix,
                        ended_at_unix,
                    )
                    || incident.recovered_at_unix.is_some_and(|recovered_at| {
                        timestamp_in_interval(recovered_at, started_at_unix, ended_at_unix)
                    })
            });
            session.additional.retain(|incident| {
                incident.open
                    || timestamp_in_interval(
                        incident.detected_at_unix,
                        started_at_unix,
                        ended_at_unix,
                    )
                    || incident.recovered_at_unix.is_some_and(|recovered_at| {
                        timestamp_in_interval(recovered_at, started_at_unix, ended_at_unix)
                    })
            });
            !session.detailed.is_empty() || !session.additional.is_empty()
        });
        if selected.sessions.is_empty() {
            return Ok(None);
        }
        let incidents = selected.sessions.iter().flat_map(|session| {
            session
                .detailed
                .iter()
                .map(|incident| (&incident.id, incident.open))
                .chain(
                    session
                        .additional
                        .iter()
                        .map(|incident| (&incident.id, incident.open)),
                )
        });
        let incident_ids = incidents.clone().map(|(id, _open)| id.clone()).collect();
        let open_incident_ids = incidents
            .filter(|(_id, open)| *open)
            .map(|(id, _open)| id.clone())
            .collect();
        let payload = bounded_snapshot_payload(&mut selected)?;
        Ok(Some(NetworkIncidentSnapshot {
            payload,
            incident_ids,
            open_incident_ids,
        }))
    }

    pub(crate) fn prune_snapshot(
        &self,
        connection_id: &str,
        snapshot: &NetworkIncidentSnapshot,
        retain_open: bool,
    ) -> io::Result<()> {
        let _archive_guard = self.lock_archive()?;
        let mut archive = read_archive(&self.path)?;
        let incident_ids = snapshot
            .incident_ids
            .iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>();
        for session in &mut archive.sessions {
            if session.connection_lease_id != connection_id {
                continue;
            }
            session.detailed.retain(|incident| {
                !incident_ids.contains(incident.id.as_str())
                    || retain_open && snapshot.open_incident_ids.contains(&incident.id)
            });
            session.additional.retain(|incident| {
                !incident_ids.contains(incident.id.as_str())
                    || retain_open && snapshot.open_incident_ids.contains(&incident.id)
            });
        }
        archive
            .sessions
            .retain(|session| !session.detailed.is_empty() || !session.additional.is_empty());
        write_archive(&self.path, &archive)
    }

    fn record_detection(
        &self,
        connection_id: &str,
        detected_at_unix: i64,
        samples: Vec<NetworkIncidentSample>,
    ) -> io::Result<()> {
        let _archive_guard = self.lock_archive()?;
        let mut archive = read_archive(&self.path)?;
        let device_id = self.current_device_id()?;
        let session = archive_session(&mut archive, connection_id, device_id.as_deref());
        if session.detailed.len() < MAX_DETAILED_INCIDENTS {
            session.detailed.push(NetworkIncident {
                id: Uuid::new_v4().to_string(),
                kind: "suspected_data_path_stall".to_string(),
                detected_at_unix,
                recovered_at_unix: None,
                duration_ms: None,
                open: true,
                samples,
            });
        } else {
            session.additional.push(NetworkIncidentSummary {
                id: Uuid::new_v4().to_string(),
                kind: "suspected_data_path_stall".to_string(),
                detected_at_unix,
                recovered_at_unix: None,
                duration_ms: None,
                open: true,
            });
        }
        write_archive(&self.path, &archive)
    }

    fn record_recovery(
        &self,
        connection_id: &str,
        detected_at_unix: i64,
        recovered_at_unix: i64,
    ) -> io::Result<()> {
        let _archive_guard = self.lock_archive()?;
        let mut archive = read_archive(&self.path)?;
        if let Some(incident) = archive
            .sessions
            .iter_mut()
            .find(|session| session.connection_lease_id == connection_id)
            .and_then(|session| {
                session
                    .detailed
                    .iter_mut()
                    .find(|incident| incident.detected_at_unix == detected_at_unix)
            })
        {
            incident.recovered_at_unix = Some(recovered_at_unix);
            incident.duration_ms =
                Some(recovered_at_unix.saturating_sub(detected_at_unix).max(0) as u64 * 1_000);
            incident.open = false;
            write_archive(&self.path, &archive)?;
        } else if let Some(incident) = archive
            .sessions
            .iter_mut()
            .find(|session| session.connection_lease_id == connection_id)
            .and_then(|session| {
                session
                    .additional
                    .iter_mut()
                    .find(|incident| incident.detected_at_unix == detected_at_unix)
            })
        {
            incident.recovered_at_unix = Some(recovered_at_unix);
            incident.duration_ms =
                Some(recovered_at_unix.saturating_sub(detected_at_unix).max(0) as u64 * 1_000);
            incident.open = false;
            write_archive(&self.path, &archive)?;
        }
        Ok(())
    }

    fn lock_archive(&self) -> io::Result<std::sync::MutexGuard<'_, ()>> {
        self.archive_gate
            .lock()
            .map_err(|_| io::Error::other("network incident archive lock poisoned"))
    }
}

fn timestamp_in_interval(value: i64, started_at: Option<i64>, ended_at: Option<i64>) -> bool {
    started_at.is_none_or(|start| value >= start) && ended_at.is_none_or(|end| value <= end)
}

fn serialize_archive(archive: &NetworkIncidentArchive) -> io::Result<String> {
    serde_json::to_string(archive)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn bounded_snapshot_payload(archive: &mut NetworkIncidentArchive) -> io::Result<String> {
    let mut payload = serialize_archive(archive)?;
    if payload.len() <= MAX_SNAPSHOT_PAYLOAD_BYTES {
        return Ok(payload);
    }

    for session in &mut archive.sessions {
        compact_additional_incidents(session);
        for incident in &mut session.detailed {
            compact_samples(&mut incident.samples);
        }
    }
    payload = serialize_archive(archive)?;
    if payload.len() <= MAX_SNAPSHOT_PAYLOAD_BYTES {
        return Ok(payload);
    }

    for session in &mut archive.sessions {
        for incident in &mut session.detailed {
            incident.samples.clear();
        }
    }
    payload = serialize_archive(archive)?;
    if payload.len() <= MAX_SNAPSHOT_PAYLOAD_BYTES {
        return Ok(payload);
    }

    for session in &mut archive.sessions {
        aggregate_detailed_incidents(session);
    }
    payload = serialize_archive(archive)?;
    while payload.len() > MAX_SNAPSHOT_PAYLOAD_BYTES && archive.sessions.len() > 1 {
        let omitted = archive.sessions.remove(0);
        record_omitted_session(archive, &omitted);
        payload = serialize_archive(archive)?;
    }
    if payload.len() > MAX_SNAPSHOT_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "network incident snapshot cannot be compacted to the report limit",
        ));
    }
    Ok(payload)
}

fn compact_samples(samples: &mut Vec<NetworkIncidentSample>) {
    if samples.len() <= MAX_COMPACTED_SAMPLES_PER_INCIDENT {
        return;
    }
    let head = MAX_COMPACTED_SAMPLES_PER_INCIDENT / 2;
    let tail = MAX_COMPACTED_SAMPLES_PER_INCIDENT - head;
    let mut compacted = samples[..head].to_vec();
    compacted.extend_from_slice(&samples[samples.len() - tail..]);
    *samples = compacted;
}

fn compact_additional_incidents(session: &mut NetworkIncidentSession) {
    if session.additional.len() <= MAX_COMPACTED_ADDITIONAL_INCIDENTS {
        return;
    }
    let original = std::mem::take(&mut session.additional);
    let mut retained = vec![false; original.len()];
    for sample in 0..MAX_COMPACTED_ADDITIONAL_INCIDENTS {
        let index =
            sample.saturating_mul(original.len() - 1) / (MAX_COMPACTED_ADDITIONAL_INCIDENTS - 1);
        retained[index] = true;
    }
    let mut omitted_count = 0_u64;
    let mut first = None;
    let mut last = None;
    for (index, incident) in original.into_iter().enumerate() {
        if retained[index] {
            session.additional.push(incident);
        } else {
            omitted_count = omitted_count.saturating_add(1);
            first = min_optional(first, Some(incident.detected_at_unix));
            last = max_optional(last, Some(incident.detected_at_unix));
        }
    }
    session.additional_count = session.additional_count.saturating_add(omitted_count);
    session.first_additional_at_unix = min_optional(session.first_additional_at_unix, first);
    session.last_additional_at_unix = max_optional(session.last_additional_at_unix, last);
}

fn aggregate_detailed_incidents(session: &mut NetworkIncidentSession) {
    if session.detailed.is_empty() {
        return;
    }
    let count = session.detailed.len() as u64;
    let first = session
        .detailed
        .iter()
        .map(|incident| incident.detected_at_unix)
        .min();
    let last = session
        .detailed
        .iter()
        .map(|incident| incident.detected_at_unix)
        .max();
    session.detailed.clear();
    session.additional_count = session.additional_count.saturating_add(count);
    session.first_additional_at_unix = min_optional(session.first_additional_at_unix, first);
    session.last_additional_at_unix = max_optional(session.last_additional_at_unix, last);
}

fn record_omitted_session(archive: &mut NetworkIncidentArchive, session: &NetworkIncidentSession) {
    let count = session
        .additional_count
        .saturating_add(session.additional.len() as u64)
        .saturating_add(session.detailed.len() as u64);
    let first = session
        .first_additional_at_unix
        .into_iter()
        .chain(
            session
                .detailed
                .iter()
                .map(|incident| incident.detected_at_unix),
        )
        .chain(
            session
                .additional
                .iter()
                .map(|incident| incident.detected_at_unix),
        )
        .min();
    let last = session
        .last_additional_at_unix
        .into_iter()
        .chain(
            session
                .detailed
                .iter()
                .map(|incident| incident.detected_at_unix),
        )
        .chain(
            session
                .additional
                .iter()
                .map(|incident| incident.detected_at_unix),
        )
        .max();
    let compaction = archive.compaction.get_or_insert(NetworkIncidentCompaction {
        omitted_session_count: 0,
        omitted_incident_count: 0,
        first_omitted_at_unix: None,
        last_omitted_at_unix: None,
    });
    compaction.omitted_session_count = compaction.omitted_session_count.saturating_add(1);
    compaction.omitted_incident_count = compaction.omitted_incident_count.saturating_add(count);
    compaction.first_omitted_at_unix = min_optional(compaction.first_omitted_at_unix, first);
    compaction.last_omitted_at_unix = max_optional(compaction.last_omitted_at_unix, last);
}

fn min_optional(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

fn max_optional(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (left, right) => left.or(right),
    }
}

fn archive_session<'a>(
    archive: &'a mut NetworkIncidentArchive,
    connection_id: &str,
    device_id: Option<&str>,
) -> &'a mut NetworkIncidentSession {
    if let Some(index) = archive
        .sessions
        .iter()
        .position(|session| session.connection_lease_id == connection_id)
    {
        if archive.sessions[index].device_id.is_none() {
            archive.sessions[index].device_id = device_id.map(str::to_string);
        }
        return &mut archive.sessions[index];
    }
    archive.sessions.push(NetworkIncidentSession {
        device_id: device_id.map(str::to_string),
        connection_lease_id: connection_id.to_string(),
        detailed: Vec::new(),
        additional: Vec::new(),
        additional_count: 0,
        first_additional_at_unix: None,
        last_additional_at_unix: None,
    });
    archive.sessions.last_mut().expect("session was inserted")
}

fn read_archive(path: &Path) -> io::Result<NetworkIncidentArchive> {
    match fs::read(path) {
        Ok(bytes) => {
            let archive: NetworkIncidentArchive = serde_json::from_slice(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if archive.version != FORMAT_VERSION {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "unsupported network incident archive version {}",
                        archive.version
                    ),
                ));
            }
            Ok(archive)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(NetworkIncidentArchive::default())
        }
        Err(error) => Err(error),
    }
}

fn prepare_archive(path: &Path) -> io::Result<Option<String>> {
    match read_archive(path) {
        Ok(mut archive) => {
            let mut changed = false;
            for session in &mut archive.sessions {
                for incident in &mut session.detailed {
                    if incident.id.is_empty() {
                        incident.id = Uuid::new_v4().to_string();
                        changed = true;
                    }
                }
                for incident in &mut session.additional {
                    if incident.id.is_empty() {
                        incident.id = Uuid::new_v4().to_string();
                        changed = true;
                    }
                }
                if session.additional_count == 0 {
                    continue;
                }
                if session.additional_count > MAXIMUM_LEGACY_ADDITIONAL_INCIDENTS {
                    return quarantine_archive(path, "legacy aggregate is too large");
                }
                let first = session
                    .first_additional_at_unix
                    .or(session.last_additional_at_unix)
                    .unwrap_or_default();
                let last = session.last_additional_at_unix.unwrap_or(first).max(first);
                let denominator = session.additional_count.saturating_sub(1).max(1);
                for index in 0..session.additional_count {
                    let detected_at_unix = first.saturating_add(
                        last.saturating_sub(first).saturating_mul(index as i64)
                            / denominator as i64,
                    );
                    session.additional.push(NetworkIncidentSummary {
                        id: Uuid::new_v4().to_string(),
                        kind: "suspected_data_path_stall".to_string(),
                        detected_at_unix,
                        recovered_at_unix: None,
                        duration_ms: None,
                        open: false,
                    });
                }
                session.additional_count = 0;
                session.first_additional_at_unix = None;
                session.last_additional_at_unix = None;
                changed = true;
            }
            if changed {
                write_archive(path, &archive)?;
            }
            Ok(None)
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            quarantine_archive(path, &error.to_string())
        }
        Err(error) => Err(error),
    }
}

fn quarantine_archive(path: &Path, reason: &str) -> io::Result<Option<String>> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("network incident path has no parent"))?;
    let quarantine = parent.join(format!(
        "network-incidents.corrupt-{}-{}.json",
        unix_now(),
        Uuid::new_v4()
    ));
    fs::rename(path, &quarantine)?;
    sync_directory(parent)?;
    Ok(Some(format!(
        "{reason}; archive quarantined as {}",
        quarantine
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("network-incidents.corrupt.json")
    )))
}

fn write_archive(path: &Path, archive: &NetworkIncidentArchive) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("network incident path has no parent"))?;
    let encoded = serde_json::to_vec(archive)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(&encoded)?;
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

fn counter_delta(previous: Option<u64>, current: u64) -> u64 {
    previous.map_or(0, |value| {
        if current >= value {
            current - value
        } else {
            current
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(received: u64, sent: u64, handshake: u64) -> TunnelMetrics {
        TunnelMetrics {
            received_bytes: received,
            sent_bytes: sent,
            latest_handshake_epoch_millis: Some(handshake),
            probe_target: None,
        }
    }

    #[test]
    fn records_and_recovers_a_bounded_incident() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();
        let mut previous = sample(100, 100, 10_000);
        for second in 10..=21 {
            let current = sample(100, 100 + (second - 9) as u64 * 200, 10_000);
            recorder
                .observe("lease-1", &current, Some(&previous), second)
                .unwrap();
            previous = current;
        }
        let recovered = sample(200, 200, 10_000);
        recorder
            .observe("lease-1", &recovered, Some(&previous), 22)
            .unwrap();

        let payload = recorder
            .snapshot(Some("lease-1"), None, Some(0), Some(30))
            .unwrap()
            .unwrap()
            .payload;
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let incident = &parsed["sessions"][0]["detailed"][0];
        assert_eq!(incident["recovered_at_unix"], 22);
        assert_eq!(incident["duration_ms"], 2_000);
        assert!(incident["samples"].as_array().unwrap().len() <= MAX_SAMPLES);
    }

    #[test]
    fn prunes_materialized_incidents_without_touching_newer_ones() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();
        recorder
            .record_detection("lease-1", 10, Vec::new())
            .unwrap();
        let materialized = recorder
            .snapshot(Some("lease-1"), None, Some(0), Some(20))
            .unwrap()
            .unwrap();
        recorder
            .record_detection("lease-1", 20, Vec::new())
            .unwrap();

        recorder
            .prune_snapshot("lease-1", &materialized, false)
            .unwrap();

        let payload = recorder
            .snapshot(Some("lease-1"), None, Some(0), Some(40))
            .unwrap()
            .unwrap()
            .payload;
        assert!(!payload.contains("\"detected_at_unix\":10"));
        assert!(payload.contains("\"detected_at_unix\":20"));
    }

    #[test]
    fn checkpoint_retains_an_open_incident_until_its_recovery_is_reported() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();
        recorder
            .record_detection("lease-1", 10, Vec::new())
            .unwrap();
        let checkpoint = recorder
            .snapshot(Some("lease-1"), None, Some(0), Some(20))
            .unwrap()
            .unwrap();

        recorder.record_recovery("lease-1", 10, 30).unwrap();
        recorder
            .prune_snapshot("lease-1", &checkpoint, true)
            .unwrap();

        let recovered = recorder
            .snapshot(Some("lease-1"), None, Some(20), Some(40))
            .unwrap()
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&recovered.payload).unwrap();
        let incident = &payload["sessions"][0]["detailed"][0];
        assert_eq!(incident["detected_at_unix"], 10);
        assert_eq!(incident["recovered_at_unix"], 30);
        assert_eq!(incident["duration_ms"], 20_000);

        recorder
            .prune_snapshot("lease-1", &recovered, false)
            .unwrap();
        assert!(recorder
            .snapshot(Some("lease-1"), None, None, None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn additional_incidents_are_selected_by_their_own_timestamps() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();
        for detected_at in [10, 20, 30, 40, 50] {
            recorder
                .record_detection("lease-1", detected_at, Vec::new())
                .unwrap();
            recorder
                .record_recovery("lease-1", detected_at, detected_at + 1)
                .unwrap();
        }

        let selected = recorder
            .snapshot(Some("lease-1"), None, Some(45), Some(55))
            .unwrap()
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&selected.payload).unwrap();
        let additional = payload["sessions"][0]["additional"].as_array().unwrap();
        assert_eq!(additional.len(), 1);
        assert_eq!(additional[0]["detected_at_unix"], 50);

        recorder
            .prune_snapshot("lease-1", &selected, false)
            .unwrap();
        let remaining = recorder
            .snapshot(Some("lease-1"), None, Some(0), Some(60))
            .unwrap()
            .unwrap()
            .payload;
        assert!(remaining.contains("\"detected_at_unix\":40"));
        assert!(!remaining.contains("\"detected_at_unix\":50"));
    }

    #[test]
    fn large_snapshot_is_compacted_below_the_panel_limit_without_losing_ids() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();
        for detected_at in 0..500 {
            recorder
                .record_detection("lease-1", detected_at, Vec::new())
                .unwrap();
        }

        let selected = recorder
            .snapshot(Some("lease-1"), None, None, None)
            .unwrap()
            .unwrap();
        assert!(selected.payload.len() <= MAX_SNAPSHOT_PAYLOAD_BYTES);
        assert_eq!(selected.incident_ids.len(), 500);
        let payload: serde_json::Value = serde_json::from_str(&selected.payload).unwrap();
        assert_eq!(
            payload["sessions"][0]["additional"]
                .as_array()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(payload["sessions"][0]["additional_count"], 433);

        recorder
            .prune_snapshot("lease-1", &selected, false)
            .unwrap();
        assert!(recorder
            .snapshot(Some("lease-1"), None, None, None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn ignores_one_idle_outbound_packet_without_inbound_traffic() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();
        let mut previous = sample(100, 100, 10_000);
        for second in 10..=21 {
            let current = sample(100, 101, 10_000);
            recorder
                .observe("lease-1", &current, Some(&previous), second)
                .unwrap();
            previous = current;
        }

        assert!(recorder
            .snapshot(Some("lease-1"), None, Some(0), Some(30))
            .unwrap()
            .is_none());
    }

    #[test]
    fn first_cumulative_sample_is_only_a_baseline() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();
        recorder
            .observe("lease-1", &sample(0, 10_000_000, 10_000), None, 10)
            .unwrap();
        recorder
            .observe("lease-1", &sample(0, 10_000_000, 10_000), None, 30)
            .unwrap();

        assert!(recorder
            .snapshot(Some("lease-1"), None, Some(0), Some(40))
            .unwrap()
            .is_none());
    }

    #[test]
    fn spaced_keepalives_do_not_open_an_incident() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();
        let baseline = sample(100, 100, 10_000);
        let first = sample(100, 164, 10_000);
        recorder
            .observe("lease-1", &first, Some(&baseline), 10)
            .unwrap();
        let idle = sample(100, 164, 10_000);
        recorder
            .observe("lease-1", &idle, Some(&first), 25)
            .unwrap();
        let second = sample(100, 228, 10_000);
        recorder
            .observe("lease-1", &second, Some(&idle), 35)
            .unwrap();
        recorder
            .observe("lease-1", &second, Some(&second), 45)
            .unwrap();

        assert!(recorder
            .snapshot(Some("lease-1"), None, Some(0), Some(50))
            .unwrap()
            .is_none());
    }

    #[test]
    fn reset_allows_the_same_connection_id_to_start_a_fresh_detection_session() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();
        let mut previous = sample(100, 100, 10_000);
        for second in 10..=21 {
            let current = sample(100, 100 + (second - 9) as u64 * 200, 10_000);
            recorder
                .observe("lease-1", &current, Some(&previous), second)
                .unwrap();
            previous = current;
        }
        let stopped = recorder
            .snapshot(Some("lease-1"), None, Some(0), Some(25))
            .unwrap()
            .unwrap();
        recorder.prune_snapshot("lease-1", &stopped, false).unwrap();
        recorder.reset_detector().unwrap();

        let mut previous = sample(100, 100, 10_000);
        for second in 30..=41 {
            let current = sample(100, 100 + (second - 29) as u64 * 200, 10_000);
            recorder
                .observe("lease-1", &current, Some(&previous), second)
                .unwrap();
            previous = current;
        }

        let payload = recorder
            .snapshot(Some("lease-1"), None, Some(20), Some(50))
            .unwrap()
            .unwrap()
            .payload;
        assert!(payload.contains("\"detected_at_unix\":40"));
    }

    #[test]
    fn corrupt_archive_is_quarantined_instead_of_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network-incidents.json");
        fs::write(&path, b"not-json").unwrap();

        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();

        assert!(recorder.startup_warning().is_some());
        assert!(!path.exists());
        let quarantine = fs::read_dir(directory.path())
            .unwrap()
            .flatten()
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("network-incidents.corrupt-")
            })
            .expect("quarantined archive");
        assert_eq!(fs::read(quarantine.path()).unwrap(), b"not-json");
    }

    #[test]
    fn migrates_legacy_aggregate_into_individually_selectable_incidents() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network-incidents.json");
        fs::write(
            &path,
            br#"{"version":1,"sessions":[{"connection_lease_id":"lease-1","detailed":[],"additional_count":3,"first_additional_at_unix":40,"last_additional_at_unix":50}]}"#,
        )
        .unwrap();

        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();

        let selected = recorder
            .snapshot(Some("lease-1"), None, Some(44), Some(46))
            .unwrap()
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&selected.payload).unwrap();
        let additional = payload["sessions"][0]["additional"].as_array().unwrap();
        assert_eq!(additional.len(), 1);
        assert_eq!(additional[0]["detected_at_unix"], 45);
        assert!(additional[0]["id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()));

        let persisted = fs::read_to_string(path).unwrap();
        assert!(!persisted.contains("additional_count"));
        assert!(!persisted.contains("first_additional_at_unix"));
        assert!(!persisted.contains("last_additional_at_unix"));
    }

    #[test]
    fn manual_snapshot_is_scoped_to_the_current_device() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = NetworkIncidentRecorder::new(directory.path()).unwrap();
        recorder.set_current_device("device-1").unwrap();
        recorder
            .record_detection("lease-1", 10, Vec::new())
            .unwrap();
        recorder.set_current_device("device-2").unwrap();
        recorder
            .record_detection("lease-2", 20, Vec::new())
            .unwrap();

        let payload = recorder
            .snapshot(None, Some("device-2"), None, None)
            .unwrap()
            .unwrap()
            .payload;
        assert!(!payload.contains("lease-1"));
        assert!(payload.contains("lease-2"));
    }
}
