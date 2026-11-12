use nelomai_client_storage::RuntimePaths;
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tauri::Manager;
use uuid::Uuid;

mod native;

const MAX_WIRE_BYTES: usize = 384 * 1024;
const MAX_APPLICATION_BYTES: usize = 128 * 1024;
const MAX_APPLICATION_RECORD_BYTES: usize = MAX_APPLICATION_BYTES - 256;
const MAX_SOURCE_BYTES: usize = 24 * 1024;
const MAX_ACTIVE_SOURCE_BYTES: usize = 8 * 1024;
// Reserve room for both slots' first versions and the two common logs.
const MAX_PRIORITY_SOURCE_BYTES: usize = 7 * 1024;
const MAX_RUNTIME_VERSIONS: usize = 4;
const MAX_VERSION_ENTRIES: usize = 64;
const LOG_FILES: [&str; 7] = [
    "application.jsonl",
    "application.previous.jsonl",
    "auth-login.jsonl",
    "auth-login.previous.jsonl",
    "auth-refresh.jsonl",
    "auth-refresh.previous.jsonl",
    "update.jsonl",
];

#[derive(Clone)]
pub(crate) struct DesktopSupportReport {
    summary: ReportSummary,
    bytes: Arc<[u8]>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReportSummary {
    report_id: String,
    bytes: usize,
    log_sources: usize,
    incomplete_sources: usize,
    service_available: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct CommonFailureStage(pub(crate) &'static str, pub(crate) Option<&'static str>);

/// The root admitted by the common owner or supplied by its runtime bootstrap.
pub(crate) struct SupportDataRoot(pub(crate) PathBuf);

fn support_data_root(verified: Option<PathBuf>, fallback: Option<PathBuf>) -> Option<PathBuf> {
    // Before the owner is ready, resolve the system-derived data location
    // as the owner would. All paths beneath this root are still opened without links.
    verified.or_else(|| fallback?.canonicalize().ok())
}

#[derive(Default)]
pub(crate) struct SupportReportState {
    main: tokio::sync::Mutex<Option<DesktopSupportReport>>,
    startup_failure: tokio::sync::Mutex<Option<DesktopSupportReport>>,
    support_diagnostics: tokio::sync::Mutex<Option<DesktopSupportReport>>,
}

impl SupportReportState {
    fn report_for(&self, label: &str) -> Option<&tokio::sync::Mutex<Option<DesktopSupportReport>>> {
        match label {
            "main" => Some(&self.main),
            "startup-failure" => Some(&self.startup_failure),
            "support-diagnostics" => Some(&self.support_diagnostics),
            _ => None,
        }
    }

    fn lock(
        window: &tauri::WebviewWindow,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<DesktopSupportReport>>, &'static str> {
        let state = window
            .try_state::<Self>()
            .ok_or("diagnostics_unavailable")?;
        state
            .inner()
            .report_for(window.label())
            .ok_or("window_not_allowed")?
            .try_lock()
            .map_err(|_| "diagnostics_busy")
    }
}

#[tauri::command]
pub(crate) async fn app_collect_support_diagnostics(
    window: tauri::WebviewWindow,
) -> Result<ReportSummary, &'static str> {
    let mut current = SupportReportState::lock(&window)?;
    let verified_root = window
        .try_state::<SupportDataRoot>()
        .map(|root| root.0.clone());
    let fallback_root = verified_root
        .is_none()
        .then(|| window.path().app_data_dir().ok())
        .flatten();
    let active_runtime = window
        .try_state::<Arc<crate::runtime_control::RuntimeControls>>()
        .and_then(|controls| controls.diagnostic_snapshot())
        .or_else(|| crate::container::diagnostic_runtime_identity(window.app_handle()));
    let common_owner = window.label() != "main";
    let failure_stage = window
        .try_state::<CommonFailureStage>()
        .map(|stage| *stage.inner())
        .or_else(|| {
            (window.label() == "startup-failure")
                .then_some(CommonFailureStage("common.setup", None))
        });
    let native = native::snapshot().await;
    let report = tauri::async_runtime::spawn_blocking(move || {
        let data_dir = support_data_root(verified_root, fallback_root);
        collect_with_native(
            data_dir.as_deref(),
            common_owner,
            failure_stage,
            active_runtime.as_ref(),
            Some(native),
        )
    })
    .await
    .map_err(|_| "collect_failed")??;
    let summary = report.summary.clone();
    *current = Some(report);
    Ok(summary)
}

#[tauri::command]
pub(crate) async fn app_save_support_diagnostics(
    window: tauri::WebviewWindow,
    report_id: String,
) -> Result<bool, &'static str> {
    use tauri_plugin_dialog::DialogExt;

    let current = SupportReportState::lock(&window)?;
    let report = find_report(&current, &report_id)?;
    let bytes = report.bytes.clone();
    let (selected, destination) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_file_name(format!(
            "Nelomai-diagnostics-{}.json",
            report.summary.report_id
        ))
        .add_filter("JSON", &["json"])
        .save_file(move |path| {
            let _ = selected.send(path);
        });
    let destination = destination
        .await
        .map_err(|_| "save_failed")?
        .map(|file| file.into_path().map_err(|_| "save_failed"))
        .transpose()?;
    tauri::async_runtime::spawn_blocking(move || save_snapshot(destination.as_deref(), &bytes))
        .await
        .map_err(|_| "save_failed")?
        .map_err(|_| "save_failed")
}

#[tauri::command]
pub(crate) async fn app_send_support_diagnostics(
    window: tauri::WebviewWindow,
    report_id: String,
    support_code: Option<String>,
) -> Result<String, &'static str> {
    let current = SupportReportState::lock(&window)?;
    let report = find_report(&current, &report_id)?;
    let api = nelomai_client_api::ClientApi::new(crate::PANEL_BASE)
        .map_err(|_| "support_network_unavailable")?;
    send_snapshot(
        &api,
        report,
        support_code.as_deref(),
        std::time::Duration::from_secs(20),
    )
    .await
}

fn find_report<'a>(
    current: &'a Option<DesktopSupportReport>,
    report_id: &str,
) -> Result<&'a DesktopSupportReport, &'static str> {
    current
        .as_ref()
        .filter(|report| report.summary.report_id == report_id)
        .ok_or("report_expired")
}

async fn send_snapshot(
    api: &nelomai_client_api::ClientApi,
    report: &DesktopSupportReport,
    support_code: Option<&str>,
    deadline: std::time::Duration,
) -> Result<String, &'static str> {
    use nelomai_client_api::ClientApiError;

    let receipt = tokio::time::timeout(
        deadline,
        api.upload_support_diagnostics(&report.bytes, support_code),
    )
    .await
    .map_err(|_| "support_timeout")?
    .map_err(|error| match error {
        ClientApiError::InvalidPayload {
            code: "support_code_invalid",
        } => "support_code_invalid",
        ClientApiError::InvalidErrorResponse { status } => match status.as_u16() {
            401 if support_code.is_some() => "support_code_invalid",
            404 | 405 => "support_unavailable",
            429 => "support_rate_limited",
            _ => "support_rejected",
        },
        ClientApiError::Transport(_) | ClientApiError::ControlTransportUnavailable => {
            "support_network_unavailable"
        }
        _ => "support_rejected",
    })?;
    if receipt.report_id != report.summary.report_id
        || receipt.received_bytes != report.bytes.len() as u64
    {
        return Err("support_receipt_invalid");
    }
    Ok(receipt.report_id)
}

fn save_snapshot(destination: Option<&Path>, bytes: &[u8]) -> io::Result<bool> {
    let Some(path) = destination else {
        return Ok(false);
    };
    let directory = path
        .parent()
        .filter(|dir| path.is_absolute() && path.file_name().is_some() && dir.is_dir())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid save location"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(true)
}

#[cfg(test)]
fn collect_desktop_support_report(
    data_dir: Option<&Path>,
    startup_failure: bool,
) -> Result<DesktopSupportReport, &'static str> {
    collect_with_native(
        data_dir,
        startup_failure,
        startup_failure.then_some(CommonFailureStage("common.setup", None)),
        None,
        None,
    )
}

fn numeric_version_components(version: &str) -> impl Iterator<Item = (usize, &str)> {
    version
        .split(['-', '+'])
        .next()
        .unwrap_or(version)
        .split('.')
        .map(|number| {
            let significant = number.trim_start_matches('0');
            (significant.len(), significant)
        })
}

fn collect_with_native(
    data_dir: Option<&Path>,
    common_owner: bool,
    startup_failure: Option<CommonFailureStage>,
    active_runtime: Option<&RuntimeIdentity>,
    native: Option<native::NativeSnapshot>,
) -> Result<DesktopSupportReport, &'static str> {
    let id = Uuid::new_v4().to_string();
    let mut log = SupportLog::default();
    push_record(
        &mut log.text,
        json!({
            "kind": "support.snapshot",
            "desktop_os": std::env::consts::OS,
            "startup_failure": startup_failure.is_some(),
            "startup_failure_stage": startup_failure.map(|failure| failure.0),
            "startup_failure_reason": startup_failure.and_then(|failure| failure.1),
            "launch_role": if common_owner { "common" } else { "runtime" },
            "pid": std::process::id(),
            "architecture": std::env::consts::ARCH,
            "application_version": env!("CARGO_PKG_VERSION"),
            "verified_runtime": active_runtime.map(|identity| json!({
                "slot": identity.slot,
                "runtime_version": identity.runtime_version,
                "runtime_contract_version": identity.runtime_contract_version,
                "container_version": identity.container_version,
            })),
        }),
        MAX_APPLICATION_RECORD_BYTES,
    );

    if let Some(data_dir) = data_dir {
        let source_limit = if active_runtime.is_none() {
            MAX_PRIORITY_SOURCE_BYTES
        } else {
            MAX_SOURCE_BYTES
        };
        for name in [
            "update-diagnostics.jsonl",
            "update-diagnostics.previous.jsonl",
        ] {
            let path = Path::new("common").join(name);
            log.source(
                "common",
                None,
                name,
                source_limit,
                checked_open(data_dir, &path, false).and_then(|file| read_tail(file, source_limit)),
            );
        }
    }

    let mut slots = [
        ("latest", RuntimeSlot::Latest),
        ("stable", RuntimeSlot::Stable),
    ];
    if active_runtime.is_some_and(|identity| identity.slot == RuntimeSlot::Stable) {
        slots.swap(0, 1);
    }
    let mut candidates = Vec::new();
    for (slot, runtime_slot) in slots {
        let Some(data_dir) = data_dir else {
            log.status(
                slot,
                None,
                "runtime_logs",
                "unavailable",
                Some("data_dir_unavailable"),
            );
            continue;
        };
        let state_dir = PathBuf::from("runtime").join(slot).join("state");
        let entries = match read_version_names(data_dir, &state_dir) {
            Ok(entries) => entries,
            Err(error) => {
                log.status(
                    slot,
                    None,
                    "runtime_logs",
                    "unavailable",
                    Some(log_error_reason(&error)),
                );
                continue;
            }
        };
        let active_version = active_runtime
            .filter(|identity| identity.slot == runtime_slot)
            .map(|identity| identity.runtime_version.as_str())
            .filter(|name| RuntimePaths::new(data_dir, runtime_slot, name).is_ok());
        let enumeration_truncated = entries.len() > MAX_VERSION_ENTRIES;
        let mut versions = entries
            .into_iter()
            .take(MAX_VERSION_ENTRIES)
            .filter_map(|entry| {
                let name = entry.into_string().ok()?;
                if active_version == Some(name.as_str()) {
                    return None;
                }
                RuntimePaths::new(data_dir, runtime_slot, &name).ok()?;
                Some(name)
            })
            .collect::<Vec<_>>();
        versions.sort_unstable_by(|left, right| {
            // The storage contract also accepts leading zeroes and components
            // larger than u64. Compare significant decimal digits first.
            numeric_version_components(right)
                .cmp(numeric_version_components(left))
                .then_with(|| {
                    semver::Version::parse(right)
                        .ok()
                        .cmp(&semver::Version::parse(left).ok())
                })
                .then_with(|| right.cmp(left))
        });
        if let Some(active) = active_version {
            // The verified live runtime takes priority even if enumeration is
            // capped or the user rolled back below several retained versions.
            versions.insert(0, active.to_owned());
        }
        if versions.len() > MAX_RUNTIME_VERSIONS || enumeration_truncated {
            log.status(slot, None, "runtime_logs", "truncated", None);
        }
        for (rank, version) in versions.into_iter().take(MAX_RUNTIME_VERSIONS).enumerate() {
            let source_limit = if active_version == Some(version.as_str()) {
                MAX_ACTIVE_SOURCE_BYTES
            } else if active_runtime.is_none() && rank == 0 {
                MAX_PRIORITY_SOURCE_BYTES
            } else {
                MAX_SOURCE_BYTES
            };
            candidates.push((
                rank,
                slot,
                state_dir.join(&version).join("diagnostics"),
                version,
                source_limit,
            ));
        }
    }
    if let Some(data_dir) = data_dir {
        if active_runtime.is_none() {
            // Without a verified runtime, visit both slots' newest versions first.
            candidates.sort_by_key(|(rank, ..)| *rank);
        }
        for (_, slot, dir, version, source_limit) in candidates {
            for file_name in LOG_FILES {
                log.source(
                    slot,
                    Some(&version),
                    file_name,
                    source_limit,
                    checked_open(data_dir, &dir.join(file_name), false)
                        .and_then(|file| read_tail(file, source_limit)),
                );
            }
        }
    }

    // Reserve room for the aggregate status even when no source marker fits.
    if !push_record(
        &mut log.text,
        json!({
            "kind": "support.log_summary",
            "application_budget_truncated": log.budget_truncated,
            "log_sources": log.sources,
            "incomplete_sources": log.incomplete,
        }),
        MAX_APPLICATION_BYTES,
    ) {
        return Err("collect_failed");
    }
    let bytes = serde_json::to_vec(&json!({
        "report_id": id,
        "trigger": "manual",
        "generated_at_unix": crate::current_unix_time(),
        "app_version": env!("CARGO_PKG_VERSION"),
        "architecture": std::env::consts::ARCH,
        "application_log": log.text,
        "helper_log": native.as_ref().map(|snapshot| snapshot.log.to_string()),
    }))
    .map_err(|_| "collect_failed")?;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err("report_too_large");
    }

    Ok(DesktopSupportReport {
        summary: ReportSummary {
            report_id: id,
            bytes: bytes.len(),
            log_sources: log.sources,
            incomplete_sources: log.incomplete,
            service_available: native.is_some_and(|snapshot| snapshot.service_available),
        },
        bytes: bytes.into(),
    })
}

#[derive(Default)]
struct SupportLog {
    text: String,
    sources: usize,
    incomplete: usize,
    budget_truncated: bool,
}

impl SupportLog {
    fn status(
        &mut self,
        slot: &str,
        version: Option<&str>,
        file: &str,
        result: &str,
        reason: Option<&str>,
    ) {
        self.incomplete += 1;
        let mut marker = source_result(slot, version, file, result);
        if let Some(reason) = reason {
            marker["reason"] = json!(reason);
        }
        self.budget_truncated |= !push_record(&mut self.text, marker, MAX_APPLICATION_RECORD_BYTES);
    }

    fn source(
        &mut self,
        slot: &str,
        version: Option<&str>,
        file: &str,
        source_limit: usize,
        outcome: io::Result<LogTail>,
    ) {
        let tail = match outcome {
            Ok(tail) => tail,
            Err(error) => {
                self.status(
                    slot,
                    version,
                    file,
                    "unavailable",
                    Some(log_error_reason(&error)),
                );
                return;
            }
        };
        self.sources += 1;
        let mut marker = source_result(slot, version, file, "truncated");
        if tail.malformed {
            marker["reason"] = json!("malformed_records");
        }
        let reserved = self.text.len() + marker.to_string().len() + 1;
        let mut remaining = MAX_APPLICATION_RECORD_BYTES
            .saturating_sub(reserved)
            .min(source_limit);
        let mut lines = Vec::new();
        let mut budget_truncated = false;
        for record in tail.records.into_iter().rev() {
            let line = Value::Object(record).to_string();
            let size = line.len() + 1;
            if size > remaining {
                budget_truncated = true;
                break;
            }
            remaining -= size;
            lines.push(line);
        }
        let incomplete = tail.truncated || tail.malformed || budget_truncated;
        if !incomplete {
            marker["result"] = json!("included");
        }
        let marked = push_record(&mut self.text, marker, MAX_APPLICATION_RECORD_BYTES);
        if marked {
            for line in lines.into_iter().rev() {
                self.text.push_str(&line);
                self.text.push('\n');
            }
        }
        self.incomplete += usize::from(incomplete || !marked);
        self.budget_truncated |= budget_truncated || !marked;
    }
}

fn log_error_reason(error: &io::Error) -> &'static str {
    #[cfg(unix)]
    if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        return "unsafe_path";
    }
    match error.kind() {
        io::ErrorKind::InvalidInput => "unsafe_path",
        io::ErrorKind::NotFound => "not_found",
        io::ErrorKind::PermissionDenied => "access_denied",
        _ => "read_failed",
    }
}

fn source_result(slot: &str, version: Option<&str>, file: &str, result: &str) -> Value {
    json!({
        "kind": "support.log_source",
        "slot": slot,
        "version_label": version,
        "file": file,
        "result": result,
    })
}

fn push_record(log: &mut String, value: Value, max: usize) -> bool {
    let line = value.to_string();
    if log.len() + line.len() + 1 > max {
        return false;
    }
    log.push_str(&line);
    log.push('\n');
    true
}

struct LogTail {
    records: Vec<Map<String, Value>>,
    truncated: bool,
    malformed: bool,
}

fn read_tail(mut file: File, limit: usize) -> io::Result<LogTail> {
    let length = file.metadata()?.len();
    let offset = length.saturating_sub(limit as u64);
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    file.take(limit as u64).read_to_end(&mut bytes)?;
    let mut lines = bytes.split_inclusive(|byte| *byte == b'\n');
    if offset != 0 {
        lines.next();
    }
    let mut tail = LogTail {
        records: Vec::new(),
        truncated: offset != 0,
        malformed: false,
    };
    for line in lines {
        let event = line
            .ends_with(b"\n")
            .then(|| serde_json::from_slice::<Value>(line).ok())
            .flatten()
            .filter(|value| value["kind"].is_string());
        if let Some(event) = event {
            tail.records.extend(safe_event(event));
        } else {
            tail.malformed = true;
        }
    }
    Ok(tail)
}

pub(super) fn safe_event(value: Value) -> Option<Map<String, Value>> {
    let mut event = Map::new();
    let kind = value["kind"].as_str()?;
    let known_kind = matches!(
        kind,
        "application.started"
            | "startup.runtime_ready"
            | "startup.runtime_recovery_required"
            | "startup.frontend.mounted"
            | "startup.frontend.first_frame"
            | "startup.bootstrap.begin"
            | "startup.bootstrap.failed"
            | "startup.bootstrap.ready"
            | "startup.bootstrap.slow"
            | "startup.auth_recovery.begin"
            | "ui.sign_in.bootstrap_signed_out"
            | "ui.sign_in.login_failed"
            | "ui.sign_in.logout_completed"
            | "bootstrap.completed"
            | "auth.login.begin"
            | "auth.login.requested"
            | "auth.login.failed"
            | "auth.login.complete"
            | "auth.refresh.begin"
            | "auth.refresh.replay"
            | "auth.refresh.pending"
            | "auth.refresh.complete"
            | "auth.refresh.rejected"
            | "connection.intent.started"
            | "connection.intent.retry_scheduled"
            | "connection.intent.recovered"
            | "connection.intent.terminal_failure"
            | "connection.intent.cancelled"
            | "connection.intent.network_wakeup"
            | "connection.intent.slow_recovery_notified"
            | "connection.panel_ready"
            | "connection.local_start_rejected"
            | "connection.local_start_failed"
            | "connection.local_start_succeeded"
            | "connection.handshake_established"
            | "connection.handshake_failed"
            | "connection.handshake_wait_timed_out"
            | "connection.handshake_metrics_failed"
            | "connection.handshake_gate_skipped"
            | "connection.handshake_recovered"
            | "connection.handshake_cleanup_failed"
            | "connection.udp_rebind_failed"
            | "connection.started"
            | "connection.start_failed"
            | "connection.start_compensation_failed"
            | "connection.start_compensation_storage_failed"
            | "connection.stop_accepted"
            | "connection.stopped"
            | "connection.stop_failed"
            | "desktop.redundancy.primary_report_started"
            | "desktop.redundancy.primary_report_failed"
            | "desktop.redundancy.primary_report_confirmed"
            | "desktop.redundancy.role_report_started"
            | "desktop.redundancy.role_report_succeeded"
            | "desktop.redundancy.role_report_failed"
            | "desktop.redundancy.role_confirmed"
            | "control.transport.failed"
            | "runtime.status"
            | "tunnel.recovery.power_gate"
            | "tunnel.data_plane_snapshot"
            | "tunnel.stall.classified"
            | "tunnel.stall.direct_probe_fallback"
            | "tunnel.stall.recovery_skipped"
            | "tunnel.stall.udp_rebound"
            | "tunnel.stall.recovered_after_rebind"
            | "tunnel.stall.udp_rebind_unavailable"
            | "tunnel.stall.udp_rebind_failed"
            | "tunnel.stall.local_restart_retry_skipped"
            | "tunnel.stall.local_tunnel_restarted"
            | "tunnel.stall.local_restart_verification_failed"
            | "tunnel.stall.local_restart_skipped"
            | "tunnel.stall.local_restart_failed"
            | "tunnel.stall.local_start_retry"
            | "windows.service.recovery_waiting"
            | "windows.service.status_running_after_metrics_failure"
            | "windows.service.local_restart_skipped"
            | "windows.service.local_tunnel_restarted"
            | "windows.service.local_restart_failed"
            | "diagnostics.automatic_upload_failed"
            | "diagnostics.automatic_report_uploaded"
            | "update.refresh.started"
            | "update.refresh.completed"
            | "update.refresh.failed"
            | "update.install.requested"
            | "update.phase.available"
            | "update.phase.downloading"
            | "update.phase.ready_to_restart"
            | "update.phase.awaiting_installation"
            | "update.phase.failed"
            | "update.download.started"
            | "update.download.failed"
            | "update.download.completed"
            | "update.verify.failed"
            | "update.install.failed"
            | "update.operation.failed"
            | "connection.stop_cleanup_pending"
    );
    if !known_kind {
        return None;
    }
    event.insert("kind".into(), json!(kind));
    for field in [
        "timestamp_unix",
        "duration_ms",
        "attempt",
        "delay_seconds",
        "handshake_age_seconds",
        "received_delta_bytes",
        "sent_delta_bytes",
        "runtime_contract_version",
        "downloaded",
        "total",
        "received_bytes",
        "expected_bytes",
        "http_status",
        "downloaded_bytes",
    ] {
        if let Some(number) = value[field].as_u64() {
            event.insert(field.into(), json!(number));
        }
    }
    if let Some(ok) = value["probe_succeeded"].as_bool() {
        event.insert("probe_succeeded".into(), json!(ok));
    }
    for field in ["operation_id", "request_id", "switch_id"] {
        if let Some(id) = value[field].as_str().and_then(|v| Uuid::parse_str(v).ok()) {
            event.insert(field.into(), json!(id.to_string()));
        }
    }
    if let Some(stage @ ("download" | "verification" | "manifest" | "installer" | "transition")) =
        value["stage"].as_str()
    {
        event.insert("stage".into(), json!(stage));
    }
    if kind == "runtime.status" {
        for key in ["active_slot", "selected_slot", "pending_slot"] {
            if let Some(slot @ ("latest" | "stable")) = value[key].as_str() {
                event.insert(key.into(), json!(slot));
            }
        }
        if let Some(
            phase @ ("requested" | "cleanup_handed_off" | "runtime_stopping" | "local_stopped"
            | "server_reconciling" | "auth_resuming" | "complete"),
        ) = value["switch_phase"].as_str()
        {
            event.insert("switch_phase".into(), json!(phase));
        }
        for key in ["container_version", "latest_version", "stable_version"] {
            if let Some(version) = value[key]
                .as_str()
                .and_then(|v| semver::Version::parse(v).ok())
                .filter(|v| v.pre.is_empty() && v.build.is_empty())
            {
                event.insert(key.into(), json!(version.to_string()));
            }
        }
        if let Some(result @ ("verified" | "rejected")) = value["manifest_verification"].as_str() {
            event.insert("manifest_verification".into(), json!(result));
        }
    }
    for field in ["code", "reason_class", "error_code"] {
        if let Some(code) = value[field].as_str() {
            let owner_login_reason = field == "code"
                && kind == "auth.login.failed"
                && matches!(
                    code,
                    "local_preflight_failed"
                        | "owner_timeout"
                        | "network_timeout"
                        | "connect_failed"
                        | "transport_failed"
                        | "http_server_error"
                        | "http_rejected"
                        | "invalid_http_response"
                        | "invalid_response"
                        | "local_error"
                );
            if owner_login_reason
                || (kind.starts_with("tunnel.stall.") || kind.starts_with("windows.service."))
                    && matches!(
                        code,
                        "tunnel_path_failed_direct_ok"
                            | "physical_path_failed"
                            | "recovered_before_probe"
                            | "ambiguous"
                            | "rate_limited"
                            | "connection_busy"
                            | "connection_changed"
                            | "verified_first_attempt"
                            | "verified_retry"
                            | "first_attempt"
                            | "retry"
                            | "busy"
                            | "unsupported"
                            | "unexpected_rebound"
                            | "reconnected"
                    )
                || matches!(
                    (kind, code),
                    ("connection.handshake_wait_timed_out", "initial")
                        | ("connection.handshake_gate_skipped", "metrics_unsupported")
                )
                || nelomai_client_updater::is_diagnostic_error_code(code)
                || matches!(
                    code,
                    "retryable"
                        | "refresh"
                        | "saved"
                        | "signed_out"
                        | "auth_refresh_pending"
                        | "auth_refresh_rejected"
                        | "access_expired"
                        | "temporary_network_error"
                        | "server_rejected"
                        | "storage_unavailable"
                        | "identity_mismatch"
                        | "rejected"
                        | "invalid_credentials"
                        | "network"
                        | "other"
                        | "runtime_startup_pending"
                        | "runtime_admission_pending"
                        | "runtime_admission_timeout"
                        | "runtime_admission_service_unavailable"
                        | "runtime_admission_rejected"
                        | "temporarily_unavailable"
                        | "physical_discovery_failed"
                        | "physical_route_unavailable"
                        | "physical_connect_timeout"
                        | "physical_dns_timeout"
                        | "physical_dns_failed"
                        | "physical_bind_failed"
                        | "physical_network_changed"
                        | "physical_connect_failed"
                        | "diagnostics_timeout"
                        | "tunnel_stopped"
                        | "tunnel_handshake_timeout"
                        | "sleep_or_dark_wake"
                        | "wake_grace"
                        | "update_install_preparing"
                        | "uid_mismatch"
                        | "path_mismatch"
                        | "executable_digest_mismatch"
                        | "executable_unavailable_or_changed"
                )
            {
                event.insert(field.into(), json!(code));
            }
        }
    }
    Some(event)
}

#[cfg(unix)]
fn read_version_names(root: &Path, relative: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    read_opened_version_names(checked_open(root, relative, true)?)
}

#[cfg(unix)]
fn read_opened_version_names(directory: File) -> io::Result<Vec<std::ffi::OsString>> {
    use std::os::unix::ffi::OsStrExt;

    rustix::fs::Dir::new(directory)?
        .filter_map(|entry| match entry {
            Ok(entry) => {
                let name = entry.file_name().to_bytes();
                if matches!(name, b"." | b"..") {
                    return None;
                }
                Some(Ok(std::ffi::OsStr::from_bytes(name).to_owned()))
            }
            Err(error) => Some(Err(error.into())),
        })
        .take(MAX_VERSION_ENTRIES + 1)
        .collect()
}

#[cfg(windows)]
fn read_version_names(root: &Path, relative: &Path) -> io::Result<Vec<std::ffi::OsString>> {
    let (_directory, _parents) = checked_windows_path(root, relative, true)?;
    std::fs::read_dir(root.join(relative))?
        .take(MAX_VERSION_ENTRIES + 1)
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect()
}

#[cfg(unix)]
pub(super) fn checked_open(root: &Path, relative: &Path, directory: bool) -> io::Result<File> {
    use std::ffi::CString;
    use std::fs::OpenOptions;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let mut parts = relative.components().peekable();
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid log path",
            ));
        };
        let name = CString::new(name.as_bytes())?;
        let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        if parts.peek().is_some() || directory {
            flags |= libc::O_DIRECTORY;
        }
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        current = unsafe { File::from_raw_fd(fd) };
    }
    if !directory && !current.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "log is not a file",
        ));
    }
    Ok(current)
}

#[cfg(windows)]
pub(super) fn checked_open(root: &Path, relative: &Path, directory: bool) -> io::Result<File> {
    checked_windows_path(root, relative, directory).map(|(file, _parents)| file)
}

#[cfg(windows)]
fn checked_windows_path(
    root: &Path,
    relative: &Path,
    directory: bool,
) -> io::Result<(File, Vec<File>)> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    // Keep the opened directory handles until the child is opened. Share
    // read/write so the live logger works, while disallowing a rename/delete.
    const SHARE_READ_WRITE: u32 = 0x0000_0003;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const REPARSE_ATTRIBUTE: u32 = 0x0000_0400;
    let open = |path: &Path, directory: bool| {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(SHARE_READ_WRITE)
            .custom_flags(OPEN_REPARSE_POINT | BACKUP_SEMANTICS)
            .open(path)?;
        let metadata = file.metadata()?;
        if metadata.file_attributes() & REPARSE_ATTRIBUTE != 0
            || if directory {
                !metadata.is_dir()
            } else {
                !metadata.is_file()
            }
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsafe log path",
            ));
        }
        Ok(file)
    };
    let mut parents = vec![open(root, true)?];
    let mut path = root.to_path_buf();
    let mut parts = relative.components().peekable();
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid log path",
            ));
        };
        path.push(name);
        if parts.peek().is_none() {
            return open(&path, directory).map(|file| (file, parents));
        }
        parents.push(open(&path, true)?);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "missing log path",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;

    #[test]
    fn support_snapshot_without_runtime_keeps_current_and_previous_events() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("runtime/latest/state/0.4.2/diagnostics");
        fs::create_dir_all(&logs).unwrap();
        fs::write(
            logs.join("application.jsonl"),
            "{\"kind\":\"application.started\",\"timestamp_unix\":12}\n{malformed",
        )
        .unwrap();
        fs::write(
            logs.join("application.previous.jsonl"),
            "{\"kind\":\"connection.stop_failed\",\"code\":\"diagnostics_timeout\"}\n",
        )
        .unwrap();
        let report = collect_desktop_support_report(Some(root.path()), false).unwrap();
        let value: Value = serde_json::from_slice(&report.bytes).unwrap();
        let id = uuid::Uuid::parse_str(value["report_id"].as_str().unwrap()).unwrap();
        assert_eq!(id.get_version_num(), 4);
        let log = value["application_log"].as_str().unwrap();
        assert!(log.contains("application.started"));
        assert!(log.contains("connection.stop_failed"));
        assert!(!log.contains("{malformed"));
        let source = log
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .find(|entry| entry["file"] == "application.jsonl")
            .unwrap();
        assert_eq!(source["result"], "truncated");
        assert_eq!(source["reason"], "malformed_records");
        assert!(log.contains("desktop_os"));
        assert_eq!(value["trigger"], "manual");
    }

    #[cfg(unix)]
    #[test]
    fn support_snapshot_uses_verified_relocated_data_root() {
        let sandbox = tempfile::tempdir().unwrap();
        let data = sandbox.path().join("data");
        let redirected = sandbox.path().join("relocated");
        fs::create_dir(&redirected).unwrap();
        std::os::unix::fs::symlink(&redirected, &data).unwrap();

        let owner = nelomai_client_storage::ContainerOwnerLock::try_acquire(&data).unwrap();
        let verified = SupportDataRoot(owner.root().to_owned());
        let logs = verified.0.join("runtime/latest/state/0.4.2/diagnostics");
        fs::create_dir_all(&logs).unwrap();
        fs::write(
            logs.join("application.jsonl"),
            "{\"kind\":\"application.started\",\"timestamp_unix\":12}\n",
        )
        .unwrap();

        let selected = support_data_root(Some(verified.0), Some(data.clone()));
        let report = collect_desktop_support_report(selected.as_deref(), false).unwrap();
        let report: Value = serde_json::from_slice(&report.bytes).unwrap();
        assert!(report["application_log"]
            .as_str()
            .unwrap()
            .contains("application.started"));

        let fallback = support_data_root(None, Some(data));
        let report = collect_desktop_support_report(fallback.as_deref(), true).unwrap();
        let report: Value = serde_json::from_slice(&report.bytes).unwrap();
        assert!(report["application_log"]
            .as_str()
            .unwrap()
            .contains("application.started"));
    }

    #[cfg(unix)]
    #[test]
    fn support_snapshot_enumerates_the_opened_runtime_directory() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let state = Path::new("runtime/latest/state");
        let path = root.path().join(state);
        fs::create_dir_all(path.join("0.4.2")).unwrap();
        fs::create_dir(other.path().join("1.2.3")).unwrap();

        let opened = checked_open(root.path(), state, true).unwrap();
        fs::rename(&path, path.with_file_name("original")).unwrap();
        std::os::unix::fs::symlink(other.path(), &path).unwrap();

        let names = read_opened_version_names(opened).unwrap();
        assert_eq!(names, ["0.4.2"]);
    }

    #[test]
    fn support_snapshot_bounds_wire_bytes_and_excludes_sensitive_inputs() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("runtime/latest/state/0.4.2/diagnostics");
        fs::create_dir_all(&logs).unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(b"\xff\x80invalid UTF-8\n");
        input.extend_from_slice(
            b"{\"kind\":\"auth.refresh.pending\",\"code\":\"retryable\",\"access_token\":\"synthetic-secret\"}\n",
        );
        input.extend_from_slice(
            b"{\"kind\":\"startup.synthetic-secret\",\"code\":\"synthetic-secret\"}\n",
        );
        fs::write(logs.join("auth-refresh.jsonl"), input).unwrap();
        fs::write(
            logs.join("application.jsonl"),
            "{\"kind\":\"connection.started\",\"duration_ms\":5}\n".repeat(100_000),
        )
        .unwrap();
        fs::write(logs.join("state-v1.json"), "synthetic-secret").unwrap();
        let report = collect_desktop_support_report(Some(root.path()), false).unwrap();
        assert!(report.bytes.len() <= 384 * 1024);
        let payload: Value = serde_json::from_slice(&report.bytes).unwrap();
        let log = payload["application_log"].as_str().unwrap();
        assert!(!log.contains("synthetic-secret"));
        assert!(!log.contains("invalid UTF-8"));
        assert!(log.contains("auth.refresh.pending"));
        assert!(log.contains("truncated"));
    }

    #[test]
    fn support_snapshot_keeps_owner_login_and_local_tunnel_failure_reasons() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("runtime/latest/state/0.4.2/diagnostics");
        fs::create_dir_all(&logs).unwrap();
        fs::write(
            logs.join("auth-login.jsonl"),
            concat!(
                "{\"kind\":\"auth.login.failed\",\"code\":\"network_timeout\",\"raw\":\"private login detail\"}\n",
                "{\"kind\":\"auth.login.failed\",\"code\":\"http_rejected\"}\n",
            ),
        )
        .unwrap();
        fs::write(
            logs.join("application.jsonl"),
            concat!(
                "{\"kind\":\"connection.local_start_succeeded\"}\n",
                "{\"kind\":\"connection.handshake_wait_timed_out\",\"code\":\"initial\"}\n",
                "{\"kind\":\"connection.handshake_failed\",\"code\":\"tunnel_handshake_timeout\"}\n",
                "{\"kind\":\"connection.local_start_failed\",\"code\":\"private native error\"}\n",
                "{\"kind\":\"desktop.redundancy.role_report_failed\",\"code\":\"temporary_network_error\"}\n",
                "{\"kind\":\"startup.runtime_recovery_required\",\"code\":\"runtime_admission_timeout\"}\n",
                "{\"kind\":\"startup.runtime_recovery_required\",\"code\":\"runtime_admission_service_unavailable\"}\n",
                "{\"kind\":\"startup.runtime_recovery_required\",\"code\":\"auth_refresh_rejected\"}\n",
                "{\"kind\":\"startup.runtime_recovery_required\",\"code\":\"runtime_admission_rejected\"}\n",
                "{\"kind\":\"tunnel.stall.classified\",\"code\":\"tunnel_path_failed_direct_ok\"}\n",
                "{\"kind\":\"tunnel.stall.local_tunnel_restarted\",\"code\":\"verified_retry\"}\n",
                "{\"kind\":\"tunnel.stall.local_restart_failed\",\"code\":\"private restart detail\"}\n",
                "{\"kind\":\"windows.service.recovery_waiting\",\"code\":\"private service detail\"}\n",
                "{\"kind\":\"windows.service.local_restart_skipped\",\"code\":\"rate_limited\"}\n",
                "{\"kind\":\"windows.service.local_tunnel_restarted\"}\n",
            ),
        )
        .unwrap();
        let report = collect_desktop_support_report(Some(root.path()), false).unwrap();
        let payload: Value = serde_json::from_slice(&report.bytes).unwrap();
        let log = payload["application_log"].as_str().unwrap();
        let events: Vec<Value> = log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for (kind, code) in [
            ("auth.login.failed", "network_timeout"),
            ("auth.login.failed", "http_rejected"),
            ("connection.handshake_wait_timed_out", "initial"),
            ("connection.handshake_failed", "tunnel_handshake_timeout"),
            (
                "desktop.redundancy.role_report_failed",
                "temporary_network_error",
            ),
            (
                "startup.runtime_recovery_required",
                "runtime_admission_timeout",
            ),
            (
                "startup.runtime_recovery_required",
                "runtime_admission_service_unavailable",
            ),
            ("startup.runtime_recovery_required", "auth_refresh_rejected"),
            (
                "startup.runtime_recovery_required",
                "runtime_admission_rejected",
            ),
            ("tunnel.stall.classified", "tunnel_path_failed_direct_ok"),
            ("tunnel.stall.local_tunnel_restarted", "verified_retry"),
            ("windows.service.local_restart_skipped", "rate_limited"),
        ] {
            assert!(
                events
                    .iter()
                    .any(|event| event["kind"] == kind && event["code"] == code),
                "{kind}: {code}"
            );
        }
        assert!(events
            .iter()
            .any(|event| event["kind"] == "connection.local_start_failed"));
        for kind in [
            "tunnel.stall.local_restart_failed",
            "windows.service.recovery_waiting",
            "windows.service.local_tunnel_restarted",
        ] {
            assert!(events
                .iter()
                .any(|event| event["kind"] == kind && event.get("code").is_none()));
        }
        assert!(!log.contains("private login detail"));
        assert!(!log.contains("private native error"));
        assert!(!log.contains("private restart detail"));
        assert!(!log.contains("private service detail"));
    }

    #[test]
    fn support_snapshot_collects_contract_valid_runtime_version_directories() {
        let root = tempfile::tempdir().unwrap();
        for (version, timestamp) in [
            ("0.4.2-rc.1", 101),
            ("0.4.2+build", 102),
            ("0.04.2", 103),
            ("0.4.2-rc.1+build", 104),
            ("0.1.0", 105),
            ("0.2.0", 106),
            ("0.3.0", 107),
            ("0.3.11", 108),
        ] {
            let logs = root
                .path()
                .join("runtime/latest/state")
                .join(version)
                .join("diagnostics");
            fs::create_dir_all(&logs).unwrap();
            fs::write(
                logs.join("application.jsonl"),
                format!("{{\"kind\":\"application.started\",\"timestamp_unix\":{timestamp}}}\n"),
            )
            .unwrap();
        }
        let report = collect_desktop_support_report(Some(root.path()), false).unwrap();
        let payload: Value = serde_json::from_slice(&report.bytes).unwrap();
        let log = payload["application_log"].as_str().unwrap();
        let timestamps: Vec<u64> = log
            .lines()
            .filter_map(|line| {
                serde_json::from_str::<Value>(line).unwrap()["timestamp_unix"].as_u64()
            })
            .collect();
        for timestamp in [101, 102, 103] {
            assert!(
                timestamps.contains(&timestamp),
                "missing log from version fixture {timestamp}"
            );
        }
        assert!(!timestamps.contains(&104));
        assert!(timestamps.contains(&108));
        assert!(!timestamps.contains(&105));
    }

    #[test]
    fn support_snapshot_prioritizes_the_verified_runtime_during_rollback() {
        let root = tempfile::tempdir().unwrap();
        for patch in 11..80 {
            let logs = root
                .path()
                .join("runtime/stable/state")
                .join(format!("0.3.{patch}"))
                .join("diagnostics");
            fs::create_dir_all(&logs).unwrap();
            fs::write(
                logs.join("application.jsonl"),
                format!("{{\"kind\":\"application.started\",\"timestamp_unix\":{patch}}}\n"),
            )
            .unwrap();
        }
        for patch in 0..4 {
            let logs = root
                .path()
                .join("runtime/latest/state")
                .join(format!("0.4.{patch}"))
                .join("diagnostics");
            fs::create_dir_all(&logs).unwrap();
            let retained =
                "{\"kind\":\"application.started\",\"timestamp_unix\":99}\n".repeat(1000);
            for name in ["application.jsonl", "application.previous.jsonl"] {
                fs::write(logs.join(name), &retained).unwrap();
            }
        }
        let active_logs = root.path().join("runtime/stable/state/0.3.11/diagnostics");
        for name in [
            "application.previous.jsonl",
            "auth-login.jsonl",
            "auth-login.previous.jsonl",
            "auth-refresh.jsonl",
            "auth-refresh.previous.jsonl",
        ] {
            fs::write(
                active_logs.join(name),
                "{\"kind\":\"auth.refresh.pending\",\"code\":\"retryable\",\"timestamp_unix\":999}\n"
                    .repeat(1000),
            )
            .unwrap();
        }
        fs::write(
            active_logs.join("update.jsonl"),
            "{\"kind\":\"update.download.failed\",\"timestamp_unix\":1009}\n",
        )
        .unwrap();
        let runtime = RuntimeIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.3.11".into(),
            runtime_contract_version: 2,
            container_version: "0.4.2".into(),
            session_generation: Some(42),
        };
        let report =
            collect_with_native(Some(root.path()), true, None, Some(&runtime), None).unwrap();
        let payload: Value = serde_json::from_slice(&report.bytes).unwrap();
        let log = payload["application_log"].as_str().unwrap();
        assert!(log.contains("\"launch_role\":\"common\""));
        let header: Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
        assert_eq!(
            header["verified_runtime"],
            json!({
                "slot": "stable",
                "runtime_version": "0.3.11",
                "runtime_contract_version": 2,
                "container_version": "0.4.2",
            })
        );
        assert!(log.contains("\"timestamp_unix\":11"));
        assert!(log.contains("\"timestamp_unix\":1009"));
        let retained_event_count = log
            .lines()
            .filter(|line| {
                serde_json::from_str::<Value>(line).unwrap()["timestamp_unix"]
                    .as_u64()
                    .is_some_and(|time| time < 99)
            })
            .count();
        assert_eq!(retained_event_count, MAX_RUNTIME_VERSIONS);
        assert!(log.contains("\"result\":\"truncated\""));
    }

    #[test]
    fn support_snapshot_reserves_current_logs_when_startup_has_no_runtime_identity() {
        let root = tempfile::tempdir().unwrap();
        let noisy = "{\"kind\":\"application.started\",\"timestamp_unix\":100}\n".repeat(1200);
        let common = root.path().join("common");
        fs::create_dir_all(&common).unwrap();
        for name in [
            "update-diagnostics.jsonl",
            "update-diagnostics.previous.jsonl",
        ] {
            fs::write(common.join(name), &noisy).unwrap();
        }
        for (slot, version) in [
            ("latest", "0.4.2"),
            ("latest", "0.4.1"),
            ("stable", "0.3.11"),
        ] {
            let logs = root
                .path()
                .join("runtime")
                .join(slot)
                .join("state")
                .join(version)
                .join("diagnostics");
            fs::create_dir_all(&logs).unwrap();
            for name in LOG_FILES {
                fs::write(logs.join(name), &noisy).unwrap();
            }
            if version == "0.4.2" {
                fs::write(
                    logs.join("auth-refresh.jsonl"),
                    format!(
                        "{noisy}{{\"kind\":\"auth.refresh.pending\",\"timestamp_unix\":101}}\n"
                    ),
                )
                .unwrap();
            } else if version == "0.3.11" {
                fs::write(
                    logs.join("update.jsonl"),
                    format!("{noisy}{{\"kind\":\"application.started\",\"timestamp_unix\":102}}\n"),
                )
                .unwrap();
            }
        }

        let report = collect_desktop_support_report(Some(root.path()), true).unwrap();
        let payload: Value = serde_json::from_slice(&report.bytes).unwrap();
        let log = payload["application_log"].as_str().unwrap();
        assert!(log.contains("\"timestamp_unix\":101"));
        assert!(log.contains("\"timestamp_unix\":102"));
        assert!(report.bytes.len() <= MAX_WIRE_BYTES);
    }

    #[test]
    fn support_snapshot_keeps_newest_record_when_only_one_fits() {
        let oldest = json!({"kind": "application.started", "timestamp_unix": 100});
        let newest = json!({"kind": "application.started", "timestamp_unix": 101});
        let marker = source_result("latest", Some("0.4.2"), "application.jsonl", "truncated");
        let occupied =
            MAX_APPLICATION_RECORD_BYTES - marker.to_string().len() - newest.to_string().len() - 2;
        let mut log = SupportLog {
            text: "x".repeat(occupied),
            ..SupportLog::default()
        };
        log.source(
            "latest",
            Some("0.4.2"),
            "application.jsonl",
            MAX_SOURCE_BYTES,
            Ok(LogTail {
                records: vec![
                    oldest.as_object().unwrap().clone(),
                    newest.as_object().unwrap().clone(),
                ],
                truncated: false,
                malformed: false,
            }),
        );
        assert!(log.text.contains("\"timestamp_unix\":101"));
        assert!(!log.text.contains("\"timestamp_unix\":100"));
        assert!(log.budget_truncated);
    }

    #[test]
    fn support_snapshot_exports_aggregate_truncation_when_each_source_fits() {
        let root = tempfile::tempdir().unwrap();
        let event =
            "{\"kind\":\"connection.handshake_failed\",\"code\":\"tunnel_handshake_timeout\"}\n";
        let contents = event.repeat(230);
        assert!(contents.len() < MAX_SOURCE_BYTES);
        for version in ["0.4.2", "0.4.1"] {
            let logs = root
                .path()
                .join("runtime/latest/state")
                .join(version)
                .join("diagnostics");
            fs::create_dir_all(&logs).unwrap();
            for name in LOG_FILES {
                fs::write(logs.join(name), &contents).unwrap();
            }
        }
        let report = collect_desktop_support_report(Some(root.path()), false).unwrap();
        let payload: Value = serde_json::from_slice(&report.bytes).unwrap();
        let log = payload["application_log"].as_str().unwrap();
        assert!(log.len() <= MAX_APPLICATION_BYTES);
        let entries: Vec<Value> = log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let footer = entries.last().unwrap();
        assert_eq!(footer["kind"], "support.log_summary");
        assert_eq!(footer["application_budget_truncated"], true);
        assert_eq!(footer["log_sources"], report.summary.log_sources);
        assert_eq!(
            footer["incomplete_sources"],
            report.summary.incomplete_sources
        );
        assert!(entries.iter().any(|entry| {
            entry["kind"] == "support.log_source"
                && entry["file"] != "runtime_logs"
                && entry["result"] == "truncated"
        }));
    }

    #[test]
    fn support_snapshot_saves_exact_bytes_without_runtime_or_panel() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("report.json");
        let report = collect_desktop_support_report(None, true).unwrap();
        let payload: Value = serde_json::from_slice(&report.bytes).unwrap();
        let header: Value = serde_json::from_str(
            payload["application_log"]
                .as_str()
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["startup_failure"], true);
        assert_eq!(header.get("verified_runtime"), Some(&Value::Null));
        assert!(!save_snapshot(None, &report.bytes).unwrap());
        assert!(!path.exists());
        assert!(save_snapshot(Some(&path), &report.bytes).unwrap());
        assert_eq!(fs::read(&path).unwrap(), report.bytes.as_ref());
        let unavailable = directory.path().join("missing").join("report.json");
        assert!(save_snapshot(Some(&unavailable), b"new").is_err());
        assert_eq!(fs::read(&path).unwrap(), report.bytes.as_ref());
        assert!(save_snapshot(Some(directory.path()), b"new").is_err());
        assert_eq!(fs::read(&path).unwrap(), report.bytes.as_ref());
    }

    #[tokio::test]
    async fn support_snapshot_is_retained_after_offline_send() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = nelomai_client_api::ClientApi::new(&format!(
            "http://{}",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        drop(listener);
        let current = Some(collect_desktop_support_report(None, true).unwrap());
        let expected = current.as_ref().unwrap();
        let report = find_report(&current, &expected.summary.report_id).unwrap();
        assert!(
            send_snapshot(&api, report, None, std::time::Duration::from_secs(2))
                .await
                .is_err()
        );
        let retained = find_report(&current, &expected.summary.report_id).unwrap();
        assert!(Arc::ptr_eq(&report.bytes, &retained.bytes));
        let replacement = Some(collect_desktop_support_report(None, true).unwrap());
        assert!(find_report(&replacement, &expected.summary.report_id).is_err());
    }

    #[test]
    fn support_snapshot_keeps_each_common_windows_report() {
        let state = SupportReportState::default();
        let failure = collect_desktop_support_report(None, true).unwrap();
        let tray = collect_desktop_support_report(None, false).unwrap();
        let mut failure_slot = state
            .report_for("startup-failure")
            .unwrap()
            .try_lock()
            .unwrap();
        *failure_slot = Some(failure.clone());
        let mut tray_slot = state
            .report_for("support-diagnostics")
            .unwrap()
            .try_lock()
            .unwrap();
        *tray_slot = Some(tray.clone());
        let retained = find_report(&failure_slot, &failure.summary.report_id).unwrap();
        assert!(Arc::ptr_eq(&retained.bytes, &failure.bytes));
        assert!(find_report(&tray_slot, &failure.summary.report_id).is_err());
        assert!(find_report(&tray_slot, &tray.summary.report_id).is_ok());
        assert!(state.report_for("unknown").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn support_snapshot_refuses_symlinked_log_and_runtime_directory() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        fs::write(
            other.path().join("application.jsonl"),
            "{\"kind\":\"auth.refresh.pending\"}\n",
        )
        .unwrap();
        let state = root.path().join("runtime/latest/state");
        let logs = state.join("0.4.2/diagnostics");
        fs::create_dir_all(&logs).unwrap();
        std::os::unix::fs::symlink(
            other.path().join("application.jsonl"),
            logs.join("application.jsonl"),
        )
        .unwrap();
        std::os::unix::fs::symlink(other.path(), state.join("0.4.3")).unwrap();
        fs::create_dir_all(root.path().join("runtime/stable")).unwrap();
        std::os::unix::fs::symlink(other.path(), root.path().join("runtime/stable/state")).unwrap();
        let report = collect_desktop_support_report(Some(root.path()), false).unwrap();
        let payload: Value = serde_json::from_slice(&report.bytes).unwrap();
        let log = payload["application_log"].as_str().unwrap();
        assert!(!log.contains("auth.refresh.pending"));
        let entries: Vec<Value> = log
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for (slot, version, file, reason) in [
            ("latest", json!("0.4.2"), "application.jsonl", "unsafe_path"),
            ("latest", json!("0.4.2"), "auth-refresh.jsonl", "not_found"),
            ("stable", Value::Null, "runtime_logs", "unsafe_path"),
        ] {
            assert!(
                entries.iter().any(|entry| {
                    entry["slot"] == slot
                        && entry["version_label"] == version
                        && entry["file"] == file
                        && entry["result"] == "unavailable"
                        && entry["reason"] == reason
                }),
                "{slot}/{version}/{file}: {log}"
            );
        }
    }
}
