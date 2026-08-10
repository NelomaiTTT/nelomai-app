#[cfg(desktop)]
use crate::automatic_diagnostics::{
    AutomaticObservation, DesktopAutomaticDiagnostics, PendingSeal, UploadCandidate,
};
use crate::resource_usage::ResourceSnapshot;
use nelomai_client_api::DiagnosticUploadRequest;
use nelomai_client_core::{CoreLogEvent, CoreLogger};
use nelomai_client_tunnel::TunnelMetrics;
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CURRENT_LOG: &str = "application.jsonl";
const PREVIOUS_LOG: &str = "application.previous.jsonl";
const ROTATE_AT_BYTES: u64 = 256 * 1024;
const MAX_APPLICATION_REPORT_BYTES: usize = 320 * 1024;
#[cfg(target_os = "android")]
const ANDROID_STARTUP_LOG: &str = "android-startup.jsonl";
#[cfg(target_os = "android")]
const MAX_ANDROID_STARTUP_REPORT_BYTES: usize = 16 * 1024;
#[cfg(target_os = "android")]
const ANDROID_FRONTEND_READY_MARKER: &str = "android-frontend-ready";
const MAX_HELPER_REPORT_BYTES: usize = 64 * 1024;
#[cfg(any(target_os = "android", test))]
const MAX_ANDROID_PREVIOUS_REPORT_BYTES: usize = 16 * 1024;
#[cfg(any(target_os = "android", test))]
const MAX_ANDROID_CURRENT_REPORT_BYTES: usize = 24 * 1024;
#[cfg(any(target_os = "android", test))]
const MAX_ANDROID_LOGCAT_REPORT_BYTES: usize = 20 * 1024;

pub struct AppDiagnostics {
    directory: PathBuf,
    write_gate: Mutex<()>,
    resource_baseline: ResourceSnapshot,
    #[cfg(desktop)]
    automatic: DesktopAutomaticDiagnostics,
    #[cfg(desktop)]
    automatic_resource_baseline: Mutex<Option<AutomaticResourceBaseline>>,
}

#[cfg(desktop)]
struct AutomaticResourceBaseline {
    session_id: String,
    interval_started_at: i64,
    snapshot: ResourceSnapshot,
}

#[derive(Serialize)]
struct LogRecord<'a> {
    timestamp_unix: i64,
    kind: &'a str,
    operation_id: Option<&'a str>,
    request_id: Option<&'a str>,
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
}

#[derive(Serialize)]
struct TunnelMetricsLogRecord<'a> {
    timestamp_unix: i64,
    kind: &'static str,
    operation_id: &'a str,
    received_bytes: u64,
    sent_bytes: u64,
    received_delta_bytes: u64,
    sent_delta_bytes: u64,
    latest_handshake_epoch_millis: Option<u64>,
    handshake_age_seconds: Option<u64>,
    probe_succeeded: Option<bool>,
    latency_ms: Option<u32>,
}

impl AppDiagnostics {
    pub fn new(directory: PathBuf, resource_baseline: ResourceSnapshot) -> io::Result<Self> {
        fs::create_dir_all(&directory)?;
        restrict_directory_permissions(&directory)?;
        #[cfg(desktop)]
        let automatic = DesktopAutomaticDiagnostics::new(directory.join("automatic"))?;
        #[cfg(desktop)]
        let automatic_startup_warning = automatic.startup_warning().map(str::to_string);
        let diagnostics = Self {
            #[cfg(desktop)]
            automatic,
            #[cfg(desktop)]
            automatic_resource_baseline: Mutex::new(None),
            directory,
            write_gate: Mutex::new(()),
            resource_baseline,
        };
        diagnostics.record_named("application.started", None, None, None);
        #[cfg(desktop)]
        if let Some(warning) = automatic_startup_warning {
            diagnostics.record_named("diagnostics.sent_prune_failed", None, None, Some(&warning));
        }
        Ok(diagnostics)
    }

    pub fn record_named(
        &self,
        kind: &str,
        operation_id: Option<&str>,
        request_id: Option<&str>,
        code: Option<&str>,
    ) {
        self.record_with_duration(kind, operation_id, request_id, code, None);
    }

    pub fn record_timed_named(
        &self,
        kind: &str,
        operation_id: Option<&str>,
        request_id: Option<&str>,
        code: Option<&str>,
        duration: Duration,
    ) {
        self.record_with_duration(
            kind,
            operation_id,
            request_id,
            code,
            Some(duration.as_millis().min(u64::MAX as u128) as u64),
        );
    }

    pub fn mark_frontend_ready(&self) {
        #[cfg(target_os = "android")]
        {
            let marker = self.directory.join(ANDROID_FRONTEND_READY_MARKER);
            let _ = fs::write(marker, now_unix().to_string());
        }
    }

    pub fn record_tunnel_metrics(
        &self,
        operation_id: &str,
        sample: &TunnelMetrics,
        previous: Option<&TunnelMetrics>,
        probe_result: Option<Option<u32>>,
    ) {
        let timestamp_unix = now_unix();
        let now_millis = timestamp_unix.max(0) as u64 * 1_000;
        let record = TunnelMetricsLogRecord {
            timestamp_unix,
            kind: "tunnel.data_plane_snapshot",
            operation_id,
            received_bytes: sample.received_bytes,
            sent_bytes: sample.sent_bytes,
            received_delta_bytes: counter_delta(
                previous.map(|value| value.received_bytes),
                sample.received_bytes,
            ),
            sent_delta_bytes: counter_delta(
                previous.map(|value| value.sent_bytes),
                sample.sent_bytes,
            ),
            latest_handshake_epoch_millis: sample.latest_handshake_epoch_millis,
            handshake_age_seconds: sample
                .latest_handshake_epoch_millis
                .map(|handshake| now_millis.saturating_sub(handshake) / 1_000),
            probe_succeeded: probe_result.map(|result| result.is_some()),
            latency_ms: probe_result.flatten(),
        };
        self.append_serialized(&record);
    }

    fn record_with_duration(
        &self,
        kind: &str,
        operation_id: Option<&str>,
        request_id: Option<&str>,
        code: Option<&str>,
        duration_ms: Option<u64>,
    ) {
        let record = LogRecord {
            timestamp_unix: now_unix(),
            kind,
            operation_id,
            request_id,
            code,
            duration_ms,
        };
        self.append_serialized(&record);
    }

    fn append_serialized(&self, record: &impl Serialize) {
        let Ok(mut encoded) = serde_json::to_vec(record) else {
            return;
        };
        encoded.push(b'\n');
        let Ok(_guard) = self.write_gate.lock() else {
            return;
        };
        let current = self.directory.join(CURRENT_LOG);
        let previous = self.directory.join(PREVIOUS_LOG);
        if current
            .metadata()
            .map(|metadata| metadata.len().saturating_add(encoded.len() as u64) > ROTATE_AT_BYTES)
            .unwrap_or(false)
        {
            let _ = fs::remove_file(&previous);
            let _ = fs::rename(&current, &previous);
        }
        if let Ok(mut file) = open_private_append(&current) {
            let _ = file.write_all(&encoded);
        }
    }

    #[cfg(test)]
    pub fn build_report(
        &self,
        resource_snapshot: ResourceSnapshot,
    ) -> io::Result<DiagnosticUploadRequest> {
        self.build_report_with_helper(resource_snapshot, None)
    }

    pub fn build_report_with_helper(
        &self,
        resource_snapshot: ResourceSnapshot,
        helper_override: Option<String>,
    ) -> io::Result<DiagnosticUploadRequest> {
        let _guard = self
            .write_gate
            .lock()
            .map_err(|_| io::Error::other("diagnostics lock poisoned"))?;
        let previous = read_tail(
            &self.directory.join(PREVIOUS_LOG),
            MAX_APPLICATION_REPORT_BYTES / 2,
        )?;
        let current = read_tail(
            &self.directory.join(CURRENT_LOG),
            MAX_APPLICATION_REPORT_BYTES,
        )?;
        let mut application_log = if previous.is_empty() {
            current
        } else {
            format!("{previous}{current}")
        };
        application_log = include_android_startup_log(&self.directory, application_log);
        application_log = tail_string(&application_log, MAX_APPLICATION_REPORT_BYTES);
        Ok(DiagnosticUploadRequest {
            report_id: None,
            trigger: "manual".to_string(),
            tunnel_session_id: None,
            sequence: None,
            interval_started_at_unix: None,
            interval_ended_at_unix: None,
            tunnel_running: None,
            generated_at_unix: now_unix(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            platform_version: platform_version(),
            architecture: std::env::consts::ARCH.to_string(),
            application_log,
            helper_log: bounded_helper_log(helper_override.or_else(|| helper_log(&self.directory))),
            resource_usage: Some(self.resource_baseline.report(resource_snapshot)),
        })
    }

    #[cfg(desktop)]
    pub fn set_automatic_device(&self, device_id: &str) {
        if let Err(error) = self.automatic.set_current_device(device_id) {
            self.record_named(
                "diagnostics.automatic_device_write_failed",
                None,
                None,
                Some(&error.kind().to_string()),
            );
        }
    }

    #[cfg(desktop)]
    pub fn clear_automatic_device(&self) {
        if let Err(error) = self.automatic.clear_current_device() {
            self.record_named(
                "diagnostics.automatic_device_clear_failed",
                None,
                None,
                Some(&error.kind().to_string()),
            );
        }
    }

    #[cfg(desktop)]
    pub fn observe_automatic_tunnel(
        &self,
        session_id: Option<&str>,
        tunnel_may_be_running: bool,
        now: i64,
    ) -> io::Result<AutomaticObservation> {
        self.automatic
            .observe(session_id, tunnel_may_be_running, now)
    }

    #[cfg(desktop)]
    pub fn begin_automatic_resource_interval(
        &self,
        observation: &AutomaticObservation,
        snapshot: ResourceSnapshot,
    ) {
        let Some(interval) = &observation.interval_started else {
            return;
        };
        let Ok(mut baseline) = self.automatic_resource_baseline.lock() else {
            return;
        };
        *baseline = Some(AutomaticResourceBaseline {
            session_id: interval.session_id.clone(),
            interval_started_at: interval.started_at,
            snapshot,
        });
    }

    #[cfg(desktop)]
    pub fn pending_automatic_seal(&self) -> io::Result<Option<PendingSeal>> {
        self.automatic.pending_seal()
    }

    #[cfg(desktop)]
    pub fn materialize_automatic_report(
        &self,
        seal: &PendingSeal,
        resource_snapshot: ResourceSnapshot,
        helper_override: Option<String>,
    ) -> io::Result<()> {
        let _guard = self
            .write_gate
            .lock()
            .map_err(|_| io::Error::other("diagnostics lock poisoned"))?;
        let previous = read_tail(
            &self.directory.join(PREVIOUS_LOG),
            MAX_APPLICATION_REPORT_BYTES / 2,
        )?;
        let current = read_tail(
            &self.directory.join(CURRENT_LOG),
            MAX_APPLICATION_REPORT_BYTES,
        )?;
        let application_log = tail_string(
            &if previous.is_empty() {
                current
            } else {
                format!("{previous}{current}")
            },
            MAX_APPLICATION_REPORT_BYTES,
        );
        let resource_usage = self
            .automatic_resource_baseline
            .lock()
            .map_err(|_| io::Error::other("automatic resource baseline lock poisoned"))?
            .as_ref()
            .filter(|baseline| {
                baseline.session_id == seal.session_id
                    && baseline.interval_started_at == seal.started_at
            })
            .map(|baseline| baseline.snapshot.report(resource_snapshot.clone()));
        let report = DiagnosticUploadRequest {
            report_id: Some(seal.report_id.clone()),
            trigger: seal.trigger.clone(),
            tunnel_session_id: Some(seal.session_id.clone()),
            sequence: Some(seal.sequence),
            interval_started_at_unix: Some(seal.started_at),
            interval_ended_at_unix: Some(seal.ended_at),
            tunnel_running: Some(seal.tunnel_running),
            generated_at_unix: seal.ended_at,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            platform_version: platform_version(),
            architecture: std::env::consts::ARCH.to_string(),
            application_log,
            helper_log: bounded_helper_log(helper_override.or_else(|| helper_log(&self.directory))),
            resource_usage,
        };
        drop(_guard);
        self.automatic.materialize(seal, &report)?;
        let mut baseline = self
            .automatic_resource_baseline
            .lock()
            .map_err(|_| io::Error::other("automatic resource baseline lock poisoned"))?;
        if seal.tunnel_running {
            *baseline = Some(AutomaticResourceBaseline {
                session_id: seal.session_id.clone(),
                interval_started_at: seal.ended_at,
                snapshot: resource_snapshot,
            });
        } else {
            *baseline = None;
        }
        Ok(())
    }

    #[cfg(desktop)]
    pub fn automatic_upload_candidate(&self, now: i64) -> io::Result<Option<UploadCandidate>> {
        self.automatic.upload_candidate(now)
    }

    #[cfg(desktop)]
    pub fn automatic_latest_upload_candidate(
        &self,
        now: i64,
    ) -> io::Result<Option<UploadCandidate>> {
        self.automatic.upload_latest_candidate(now)
    }

    #[cfg(desktop)]
    pub fn automatic_upload_succeeded(
        &self,
        candidate: &UploadCandidate,
        now: i64,
    ) -> io::Result<()> {
        self.automatic.upload_succeeded(candidate, now)
    }

    #[cfg(desktop)]
    pub fn automatic_upload_failed(&self, now: i64) -> io::Result<i64> {
        self.automatic.upload_failed(now)
    }
}

fn bounded_helper_log(value: Option<String>) -> Option<String> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| tail_string(&value, MAX_HELPER_REPORT_BYTES))
}

fn counter_delta(previous: Option<u64>, current: u64) -> u64 {
    previous.map_or(current, |previous| {
        if current >= previous {
            current - previous
        } else {
            current
        }
    })
}

#[cfg(target_os = "android")]
fn include_android_startup_log(directory: &Path, application_log: String) -> String {
    let native = read_tail(
        &directory.join(ANDROID_STARTUP_LOG),
        MAX_ANDROID_STARTUP_REPORT_BYTES,
    )
    .unwrap_or_default();
    combine_application_and_startup_logs(application_log, native)
}

#[cfg(not(target_os = "android"))]
fn include_android_startup_log(_directory: &Path, application_log: String) -> String {
    application_log
}

#[cfg(any(target_os = "android", test))]
fn combine_application_and_startup_logs(application_log: String, native_log: String) -> String {
    if native_log.is_empty() {
        application_log
    } else if application_log.is_empty() {
        native_log
    } else {
        format!("{application_log}{native_log}")
    }
}

impl CoreLogger for AppDiagnostics {
    fn record(&self, event: CoreLogEvent) {
        self.record_named(
            event.kind,
            event.operation_id.as_deref(),
            event.request_id.as_deref(),
            event.code.as_deref(),
        );
    }

    fn record_timed(&self, event: CoreLogEvent, duration_ms: u64) {
        self.record_with_duration(
            event.kind,
            event.operation_id.as_deref(),
            event.request_id.as_deref(),
            event.code.as_deref(),
            Some(duration_ms),
        );
    }
}

fn read_tail(path: &Path, maximum: usize) -> io::Result<String> {
    match File::open(path) {
        Ok(mut file) => {
            let length = file.metadata()?.len();
            let read_length = length.min(maximum as u64) as usize;
            file.seek(SeekFrom::Start(length.saturating_sub(read_length as u64)))?;
            let mut bytes = vec![0; read_length];
            file.read_exact(&mut bytes)?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error),
    }
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

#[cfg(unix)]
fn open_private_append(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn tail_string(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_string();
    }
    let mut start = value.len() - maximum;
    while start < value.len() && !value.is_char_boundary(start) {
        start += 1;
    }
    value[start..].to_string()
}

#[cfg(windows)]
fn helper_log_path() -> Option<PathBuf> {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .map(|root| {
            root.join("Nelomai")
                .join("Tunnel")
                .join("service-diagnostics.log")
        })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn helper_log_path() -> Option<PathBuf> {
    Some(PathBuf::from("/var/log/nelomai-tunnel.log"))
}

#[cfg(target_os = "android")]
fn helper_log(directory: &Path) -> Option<String> {
    use std::process::Command;

    let previous = read_tail(
        &directory.join("android-tunnel.previous.jsonl"),
        MAX_ANDROID_PREVIOUS_REPORT_BYTES,
    )
    .unwrap_or_default();
    let current = read_tail(
        &directory.join("android-tunnel.jsonl"),
        MAX_ANDROID_CURRENT_REPORT_BYTES,
    )
    .unwrap_or_default();
    let logcat = Command::new("/system/bin/logcat")
        .args([
            "-d",
            "-v",
            "threadtime",
            "-t",
            "500",
            "NelomaiTunnel:V",
            "AndroidRuntime:E",
            "libc:F",
            "*:S",
        ])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).replace('\0', ""))
        .unwrap_or_default();
    Some(combine_android_logs(&previous, &current, &logcat))
}

#[cfg(any(target_os = "android", test))]
fn combine_android_logs(previous: &str, current: &str, logcat: &str) -> String {
    let previous = tail_string(previous, MAX_ANDROID_PREVIOUS_REPORT_BYTES);
    let current = tail_string(current, MAX_ANDROID_CURRENT_REPORT_BYTES);
    let prefix =
        format!("[persistent.previous]\n{previous}\n[persistent.current]\n{current}\n[logcat]\n");
    let logcat_budget =
        MAX_ANDROID_LOGCAT_REPORT_BYTES.min(MAX_HELPER_REPORT_BYTES.saturating_sub(prefix.len()));
    let logcat = tail_string(logcat, logcat_budget);
    format!("{prefix}{logcat}")
}

#[cfg(not(target_os = "android"))]
fn helper_log(_directory: &Path) -> Option<String> {
    helper_log_path().and_then(|path| read_tail(&path, MAX_HELPER_REPORT_BYTES).ok())
}

#[cfg(target_os = "android")]
fn platform_version() -> Option<String> {
    use std::process::Command;

    let output = Command::new("/system/bin/getprop")
        .arg("ro.build.version.release")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(not(target_os = "android"))]
fn platform_version() -> Option<String> {
    None
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_and_builds_bounded_report() {
        let directory =
            std::env::temp_dir().join(format!("nelomai-diagnostics-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let baseline = ResourceSnapshot::capture_for_test();
        let diagnostics = AppDiagnostics::new(directory.clone(), baseline).unwrap();
        for index in 0..10_000 {
            diagnostics.record_named(
                "test.event",
                Some(&index.to_string()),
                None,
                Some("safe_code"),
            );
        }
        let report = diagnostics
            .build_report(ResourceSnapshot::capture_for_test())
            .unwrap();
        assert!(report.application_log.len() <= MAX_APPLICATION_REPORT_BYTES);
        assert!(report.application_log.contains("test.event"));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn reads_only_the_requested_tail() {
        let directory =
            std::env::temp_dir().join(format!("nelomai-tail-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("large.log");
        fs::write(&path, vec![b'x'; 2 * 1024 * 1024]).unwrap();

        let tail = read_tail(&path, 1024).unwrap();

        assert_eq!(tail.len(), 1024);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn includes_stage_duration_when_available() {
        let directory = std::env::temp_dir().join(format!(
            "nelomai-diagnostics-duration-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        let baseline = ResourceSnapshot::capture_for_test();
        let diagnostics = AppDiagnostics::new(directory.clone(), baseline).unwrap();
        diagnostics.record_timed(
            CoreLogEvent {
                kind: "connection.local_start_succeeded",
                operation_id: Some("operation-1".to_string()),
                request_id: Some("request-1".to_string()),
                code: None,
            },
            12_345,
        );

        let report = diagnostics
            .build_report(ResourceSnapshot::capture_for_test())
            .unwrap();
        let record = report
            .application_log
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|record| record["kind"] == "connection.local_start_succeeded")
            .unwrap();

        assert_eq!(record["duration_ms"], 12_345);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn keeps_persistent_android_log_when_logcat_is_large() {
        let previous = format!("{}previous-tail\n", "previous-line\n".repeat(2_000));
        let current = format!("{}current-tail\n", "current-line\n".repeat(2_000));
        let report = combine_android_logs(&previous, &current, &"logcat-line\n".repeat(20_000));

        assert!(report.len() <= MAX_HELPER_REPORT_BYTES);
        assert!(report.contains("[persistent.previous]"));
        assert!(report.contains("previous-tail"));
        assert!(report.contains("[persistent.current]"));
        assert!(report.contains("current-tail"));
        assert!(report.contains("[logcat]"));
    }

    #[test]
    fn appends_native_android_startup_stages_to_application_log() {
        let application = "{\"kind\":\"application.started\"}\n".to_string();
        let native = "{\"kind\":\"startup.android.activity_created\"}\n".to_string();

        let combined = combine_application_and_startup_logs(application, native);

        assert!(combined.contains("application.started"));
        assert!(combined.contains("startup.android.activity_created"));
    }

    #[test]
    fn records_data_plane_counters_handshake_and_probe_result() {
        let directory = std::env::temp_dir().join(format!(
            "nelomai-diagnostics-metrics-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        let diagnostics =
            AppDiagnostics::new(directory.clone(), ResourceSnapshot::capture_for_test()).unwrap();
        let previous = TunnelMetrics {
            received_bytes: 100,
            sent_bytes: 50,
            ..TunnelMetrics::default()
        };
        let sample = TunnelMetrics {
            received_bytes: 145,
            sent_bytes: 65,
            latest_handshake_epoch_millis: Some(1),
            probe_target: None,
        };

        diagnostics.record_tunnel_metrics("session-1", &sample, Some(&previous), Some(Some(42)));

        let report = diagnostics
            .build_report(ResourceSnapshot::capture_for_test())
            .unwrap();
        let record = report
            .application_log
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|record| record["kind"] == "tunnel.data_plane_snapshot")
            .unwrap();
        assert_eq!(record["received_delta_bytes"], 45);
        assert_eq!(record["sent_delta_bytes"], 15);
        assert_eq!(record["latest_handshake_epoch_millis"], 1);
        assert_eq!(record["probe_succeeded"], true);
        assert_eq!(record["latency_ms"], 42);
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn counter_delta_handles_backend_counter_reset() {
        assert_eq!(counter_delta(None, 12), 12);
        assert_eq!(counter_delta(Some(10), 14), 4);
        assert_eq!(counter_delta(Some(10), 3), 3);
    }

    #[cfg(desktop)]
    #[test]
    fn automatic_report_omits_resource_delta_without_matching_interval_baseline() {
        let directory = tempfile::tempdir().unwrap();
        let diagnostics = AppDiagnostics::new(
            directory.path().to_path_buf(),
            ResourceSnapshot::capture_for_test(),
        )
        .unwrap();
        diagnostics.set_automatic_device("device-1");
        diagnostics
            .observe_automatic_tunnel(Some("connection-1"), true, 10)
            .unwrap();
        diagnostics
            .observe_automatic_tunnel(None, false, 20)
            .unwrap();
        let seal = diagnostics.pending_automatic_seal().unwrap().unwrap();

        diagnostics
            .materialize_automatic_report(&seal, ResourceSnapshot::capture_for_test(), None)
            .unwrap();
        let candidate = diagnostics.automatic_upload_candidate(20).unwrap().unwrap();

        assert!(candidate.report.resource_usage.is_none());
    }

    #[cfg(desktop)]
    #[test]
    fn automatic_report_uses_the_current_interval_resource_baseline() {
        let directory = tempfile::tempdir().unwrap();
        let diagnostics = AppDiagnostics::new(
            directory.path().to_path_buf(),
            ResourceSnapshot::capture_for_test(),
        )
        .unwrap();
        diagnostics.set_automatic_device("device-1");
        let observation = diagnostics
            .observe_automatic_tunnel(Some("connection-1"), true, 10)
            .unwrap();
        diagnostics
            .begin_automatic_resource_interval(&observation, ResourceSnapshot::capture_for_test());
        diagnostics
            .observe_automatic_tunnel(None, false, 20)
            .unwrap();
        let seal = diagnostics.pending_automatic_seal().unwrap().unwrap();

        diagnostics
            .materialize_automatic_report(&seal, ResourceSnapshot::capture_for_test(), None)
            .unwrap();
        let candidate = diagnostics.automatic_upload_candidate(20).unwrap().unwrap();

        assert!(candidate.report.resource_usage.is_some());
    }
}
