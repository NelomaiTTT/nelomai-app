use crate::resource_usage::ResourceSnapshot;
use nelomai_client_api::DiagnosticUploadRequest;
use nelomai_client_core::{CoreLogEvent, CoreLogger};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const CURRENT_LOG: &str = "application.jsonl";
const PREVIOUS_LOG: &str = "application.previous.jsonl";
const ROTATE_AT_BYTES: u64 = 256 * 1024;
const MAX_APPLICATION_REPORT_BYTES: usize = 320 * 1024;
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

impl AppDiagnostics {
    pub fn new(directory: PathBuf, resource_baseline: ResourceSnapshot) -> io::Result<Self> {
        fs::create_dir_all(&directory)?;
        restrict_directory_permissions(&directory)?;
        let diagnostics = Self {
            directory,
            write_gate: Mutex::new(()),
            resource_baseline,
        };
        diagnostics.record_named("application.started", None, None, None);
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
        let Ok(mut encoded) = serde_json::to_vec(&record) else {
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

    pub fn build_report(
        &self,
        resource_snapshot: ResourceSnapshot,
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
        if application_log.len() > MAX_APPLICATION_REPORT_BYTES {
            application_log = tail_string(&application_log, MAX_APPLICATION_REPORT_BYTES);
        }
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
            helper_log: helper_log(&self.directory).filter(|value| !value.is_empty()),
            resource_usage: Some(self.resource_baseline.report(resource_snapshot)),
        })
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
}
