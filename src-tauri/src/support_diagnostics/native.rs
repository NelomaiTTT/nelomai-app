use serde_json::{json, Value};
use std::path::Path;
#[cfg(any(target_os = "macos", windows))]
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const PROBE_OUTPUT_LIMIT: usize = 32 * 1024;

pub(super) struct NativeSnapshot {
    pub(super) service_available: bool,
    pub(super) log: Value,
}

pub(super) async fn snapshot() -> NativeSnapshot {
    let log = platform_snapshot().await;
    NativeSnapshot {
        service_available: log["service"]["result"] == "included",
        log,
    }
}

fn unavailable(reason: &str) -> Value {
    json!({"result": "unavailable", "reason": reason})
}

fn included(value: Value) -> Value {
    json!({"result": "included", "value": value})
}

async fn run(executable: impl AsRef<Path>, args: &[&str]) -> Result<Vec<u8>, &'static str> {
    let mut command = tokio::process::Command::new(executable.as_ref());
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let mut child = command.spawn().map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => "not_installed",
        std::io::ErrorKind::PermissionDenied => "access_denied",
        _ => "probe_unavailable",
    })?;
    tokio::time::timeout(PROBE_TIMEOUT, async {
        let mut stdout = child.stdout.take().ok_or("probe_unavailable")?;
        let mut bytes = Vec::new();
        (&mut stdout)
            .take((PROBE_OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| "probe_unavailable")?;
        if bytes.len() > PROBE_OUTPUT_LIMIT {
            return Err("output_limit");
        }
        let status = child.wait().await.map_err(|_| "probe_unavailable")?;
        if status.success() {
            Ok(bytes)
        } else {
            Err("probe_failed")
        }
    })
    .await
    .map_err(|_| "timeout")?
}

async fn run_probe(
    executable: impl AsRef<Path>,
    args: &[&str],
    project: impl FnOnce(&[u8]) -> Value,
) -> Value {
    match run(executable, args).await {
        Ok(bytes) => project(&bytes),
        Err(reason) => unavailable(reason),
    }
}

#[cfg(any(not(windows), test))]
fn log_facts(bytes: &[u8]) -> Value {
    let mut events = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n').rev() {
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        let line = line.trim();
        let mut reason = None;
        for prefix in [
            "private dispatcher broker rejected: ",
            "lifecycle dispatcher broker rejected: ",
            "broker rejected: ",
        ] {
            if let Some(found) = line.rsplit_once(prefix).map(|(_, found)| found) {
                reason = match found {
                    "uid_mismatch" => Some("uid_mismatch"),
                    "sid_mismatch" => Some("sid_mismatch"),
                    "path_mismatch" => Some("path_mismatch"),
                    "executable_digest_mismatch" => Some("executable_digest_mismatch"),
                    "executable_unavailable_or_changed" => {
                        Some("executable_unavailable_or_changed")
                    }
                    _ => None,
                };
                break;
            }
        }
        let reason = reason.or_else(|| {
            if line.ends_with("dispatcher request failed: unauthorized_client") {
                Some("broker_rejected")
            } else if line.ends_with("nelomai tunnel helper request watchdog expired") {
                Some("helper_watchdog_expired")
            } else if line.contains("manager lifecycle: running") {
                Some("manager_running")
            } else if line.contains("manager lifecycle: stopped") {
                Some("manager_stopped")
            } else if line.starts_with("nelomai helper failed:") {
                Some("helper_failed")
            } else {
                None
            }
        });
        if let Some(reason) = reason {
            let timestamp = line
                .trim_start_matches('\u{feff}')
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok());
            events.push(json!({"reason": reason, "timestamp_unix": timestamp}));
        }
        #[cfg(any(target_os = "linux", test))]
        if let Some(result) = line
            .strip_prefix("nelomai-tunnel.service: Failed with result '")
            .and_then(|tail| tail.strip_suffix("'."))
            .and_then(systemd_result)
        {
            events.push(json!({"reason": "systemd_unit_failed", "service_result": result}));
        }
        if events.len() == 48 {
            return json!({"result": "truncated", "value": events});
        }
    }
    included(json!(events))
}

#[cfg(target_os = "macos")]
async fn helper_log(root: PathBuf, relative: &'static str) -> Value {
    use std::io::{Read, Seek, SeekFrom};
    tauri::async_runtime::spawn_blocking(move || {
        let result: std::io::Result<_> = (|| {
            let mut file = super::checked_open(&root, Path::new(relative), false)?;
            let length = file.metadata()?.len();
            let offset = length.saturating_sub(PROBE_OUTPUT_LIMIT as u64);
            file.seek(SeekFrom::Start(offset))?;
            let mut bytes = Vec::new();
            file.take(PROBE_OUTPUT_LIMIT as u64)
                .read_to_end(&mut bytes)?;
            let start = if offset == 0 {
                0
            } else {
                bytes
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |index| index + 1)
            };
            let end = bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |index| index + 1);
            let mut facts = log_facts(bytes.get(start..end).unwrap_or_default());
            if offset != 0 {
                facts["result"] = json!("truncated");
            }
            Ok(facts)
        })();
        match result {
            Ok(facts) => facts,
            Err(error) => unavailable(match error.kind() {
                std::io::ErrorKind::NotFound => "not_found",
                std::io::ErrorKind::PermissionDenied => "access_denied",
                _ => "log_unavailable",
            }),
        }
    })
    .await
    .unwrap_or_else(|_| unavailable("probe_unavailable"))
}

#[cfg(target_os = "macos")]
async fn platform_snapshot() -> Value {
    async fn bundle(path: &'static str) -> Value {
        let plist = format!("{path}/Contents/Info.plist");
        run_probe(
            "/usr/libexec/PlistBuddy",
            &["-c", "Print :CFBundleShortVersionString", &plist],
            |output| {
                let version = std::str::from_utf8(output)
                    .ok()
                    .and_then(|v| semver::Version::parse(v.trim()).ok())
                    .filter(|v| v.pre.is_empty() && v.build.is_empty());
                match version {
                    Some(version) => included(json!({
                        "version": version.to_string(),
                        "quarantine_present": crate::macos_installation::requires_installation_repair(Path::new(path)).ok(),
                    })),
                    None => unavailable("invalid_version"),
                }
            },
        )
        .await
    }
    let (service, log, visible, protected, events) = tokio::join!(
        run_probe(
            "/bin/launchctl",
            &["print", "system/ru.nelomai.tunnel"],
            project_launchd,
        ),
        helper_log(PathBuf::from("/private/var/log"), "nelomai-tunnel.log"),
        bundle("/Applications/Nelomai.app"),
        bundle("/Library/Application Support/Nelomai/common/Nelomai.app"),
        run_probe(
            "/usr/bin/log",
            &[
                "show", "--last", "5m", "--style", "compact", "--predicate",
                "process == \"nelomai-unix-service\" AND (messageType == error OR messageType == fault)",
            ],
            log_facts,
        ),
    );
    json!({
        "service": service,
        "service_log": log,
        "visible_bundle": visible,
        "protected_bundle": protected,
        "system_events": events,
    })
}

#[cfg(target_os = "macos")]
fn project_launchd(output: &[u8]) -> Value {
    let Ok(output) = std::str::from_utf8(output) else {
        return unavailable("invalid_output");
    };
    let field = |name: &str| {
        output.lines().find_map(|line| {
            let (key, value) = line.trim().split_once(" = ")?;
            (key == name).then_some(value)
        })
    };
    let state = match field("state") {
        Some("running") => "running",
        Some("waiting") => "waiting",
        Some("not running") => "not_running",
        Some("spawn scheduled") => "spawn_scheduled",
        _ => return unavailable("unknown_service_state"),
    };
    included(json!({
        "state": state,
        "pid": field("pid").and_then(|v| v.parse::<u32>().ok()),
        "last_exit_code": field("last exit code").and_then(|v| v.parse::<i32>().ok()),
    }))
}

#[cfg(target_os = "linux")]
async fn platform_snapshot() -> Value {
    let (service, journal) = tokio::join!(
        run_probe(
            "/usr/bin/systemctl",
            &[
                "show",
                "--no-pager",
                "--property=LoadState,ActiveState,MainPID,Result,ExecMainCode,ExecMainStatus",
                "nelomai-tunnel.service",
            ],
            project_systemd,
        ),
        run_probe(
            "/usr/bin/journalctl",
            &[
                "--unit=nelomai-tunnel.service",
                "--lines=48",
                "--since=-1h",
                "--output=cat",
                "--no-pager",
            ],
            |output| if output.starts_with(b"-- No entries --") {
                unavailable("no_readable_entries")
            } else {
                log_facts(output)
            },
        ),
    );
    json!({"service": service, "service_log": journal})
}

#[cfg(any(target_os = "linux", test))]
fn systemd_result(value: &str) -> Option<&str> {
    match value {
        "success" | "resources" | "protocol" | "timeout" | "exit-code" | "signal" | "core-dump"
        | "watchdog" | "start-limit-hit" | "oom-kill" => Some(value),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", test))]
fn project_systemd(output: &[u8]) -> Value {
    let Ok(output) = std::str::from_utf8(output) else {
        return unavailable("invalid_output");
    };
    let field = |key: &str| output.lines().find_map(|line| line.strip_prefix(key));
    if field("LoadState=") == Some("not-found") {
        return unavailable("not_installed");
    }
    let state = match field("ActiveState=") {
        Some(state @ ("active" | "inactive" | "activating" | "deactivating" | "failed")) => state,
        _ => return unavailable("unknown_service_state"),
    };
    included(json!({
        "state": state,
        "pid": field("MainPID=").and_then(|v| v.parse::<u32>().ok()).filter(|v| *v != 0),
        "service_result": field("Result=").and_then(systemd_result),
        "exec_main_code": field("ExecMainCode=").and_then(|v| v.parse::<u32>().ok()),
        "exec_main_status": field("ExecMainStatus=").and_then(|v| v.parse::<u32>().ok()),
    }))
}

#[cfg(any(windows, test))]
fn scm_event_ids(output: &[u8]) -> Vec<u32> {
    String::from_utf8_lossy(output)
        .split("<EventID")
        .skip(1)
        .filter_map(|part| {
            let (attributes, value) = part.split_once('>')?;
            if !attributes.is_empty() && !attributes.starts_with(char::is_whitespace) {
                return None;
            }
            value.split_once("</EventID>")?.0.parse::<u32>().ok()
        })
        .filter(|id| {
            matches!(
                id,
                7000 | 7001 | 7009 | 7011 | 7023 | 7024 | 7031 | 7034 | 7036
            )
        })
        .take(24)
        .collect()
}

#[cfg(windows)]
async fn platform_snapshot() -> Value {
    use nelomai_windows_service::broker_diagnostics::{
        application_denials, application_query, APPLICATION_EVENT_LIMIT,
    };
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = [0; 260];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return json!({
            "service": unavailable("system_directory_unavailable"),
            "system_events": unavailable("system_directory_unavailable"),
            "service_log": unavailable("system_directory_unavailable"),
        });
    }
    let system = PathBuf::from(OsString::from_wide(&buffer[..length]));
    let manager = nelomai_windows_service::MANAGER_SERVICE_NAME;
    let service = async {
        run_probe(system.join("sc.exe"), &["queryex", manager], |output| {
            let output = String::from_utf8_lossy(output);
            let field = |name: &str| {
                output.lines().find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    if key.trim() != name {
                        return None;
                    }
                    value.split_whitespace().next()?.parse::<u32>().ok()
                })
            };
            let Some(state) = field("STATE").filter(|value| (1..=7).contains(value)) else {
                return unavailable("unknown_service_state");
            };
            included(json!({"state_code": state, "pid": field("PID").filter(|v| *v != 0)}))
        })
        .await
    };
    let events = async {
        run_probe(
            system.join("wevtutil.exe"),
            &[
                "qe", "System", "/c:24", "/rd:true", "/f:xml",
                "/q:*[System[Provider[@Name='Service Control Manager'] and TimeCreated[timediff(@SystemTime) <= 3600000]] and EventData[Data='NelomaiTunnelManager' or Data='Nelomai Tunnel Manager']]",
            ],
            |output| included(json!(scm_event_ids(output))),
        ).await
    };
    let query = application_query();
    let count = format!("/c:{APPLICATION_EVENT_LIMIT}");
    let args = ["qe", "Application", &count, "/rd:true", "/f:xml", &query];
    let service_log = run_probe(system.join("wevtutil.exe"), &args, |output| {
        let denials = application_denials(output)
            .into_iter()
            .map(|denial| json!({"reason": denial.code()}))
            .collect::<Vec<_>>();
        included(json!(denials))
    });
    let (service, events, log) = tokio::join!(service, events, service_log);
    json!({"service": service, "system_events": events, "service_log": log})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_snapshot_reports_systemd_exit_failure_without_raw_output() {
        let service = project_systemd(
            b"LoadState=loaded\nActiveState=failed\nMainPID=0\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\nEnvironment=private\n",
        );
        assert_eq!(service["value"]["state"], "failed");
        assert_eq!(service["value"]["service_result"], "exit-code");
        assert_eq!(service["value"]["exec_main_code"], 1);
        assert_eq!(service["value"]["exec_main_status"], 1);
        assert!(!service.to_string().contains("private"));
        let journal = log_facts(b"nelomai-tunnel.service: Failed with result 'exit-code'.\nnelomai-tunnel.service: Failed with result 'private'.\n");
        assert_eq!(journal["value"].as_array().unwrap().len(), 1);
        assert_eq!(journal["value"][0]["service_result"], "exit-code");
        assert!(!journal.to_string().contains("private"));
    }

    #[test]
    fn support_snapshot_reads_classic_scm_event_ids_with_qualifiers() {
        let xml = br#"<Event><System><EventID Qualifiers="16384">7036</EventID></System></Event>
            <Event><System><EventID Qualifiers='49152'>7000</EventID></System></Event>
            <Event><System><EventID>7031</EventID></System></Event>
            <Event><System><EventID Qualifiers="16384">9999</EventID></System></Event>
            <Event><System><EventIDCopy>7034</EventID></System></Event>"#;
        assert_eq!(scm_event_ids(xml), [7036, 7000, 7031]);
    }

    #[cfg(feature = "custom-protocol")]
    #[test]
    fn support_snapshot_packaged_startup_failure_has_local_actions() {
        let context = crate::app_context();
        let html = context
            .assets()
            .get(&"startup-failure.html".into())
            .expect("packaged startup failure page");
        let script = context
            .assets()
            .get(&"startup-failure.js".into())
            .expect("packaged startup failure script");
        assert!(std::str::from_utf8(&html)
            .unwrap()
            .contains("startup-failure.js"));
        let script = std::str::from_utf8(&script).unwrap();
        for action in [
            "app_collect_support_diagnostics",
            "app_save_support_diagnostics",
            "app_send_support_diagnostics",
        ] {
            assert!(script.contains(action));
        }
        assert!(!script.contains("app_bootstrap"));
    }

    #[test]
    fn support_snapshot_projects_native_log_to_fixed_reason_codes() {
        let result = log_facts(
            b"123 broker rejected: path_mismatch\n\
              private dispatcher broker rejected: uid_mismatch\n\
              forged user path secret\n\
              42 broker rejected: secret\n",
        );
        let reasons = result["value"].as_array().unwrap();
        assert_eq!(reasons.len(), 2);
        assert_eq!(reasons[0]["reason"], "uid_mismatch");
        assert_eq!(reasons[1]["timestamp_unix"], 123);
        assert!(!result.to_string().contains("secret"));
    }

    #[tokio::test]
    async fn support_snapshot_native_probe_unavailable_does_not_block_export() {
        let directory = tempfile::tempdir().unwrap();
        let missing = run_probe(directory.path().join("missing"), &[], |_| unreachable!()).await;
        assert_eq!(missing["reason"], "not_installed");
        let native = NativeSnapshot {
            service_available: false,
            log: json!({"service": missing}),
        };
        let report = super::super::collect_with_native(
            None,
            true,
            Some(super::super::CommonFailureStage(
                "common.pre_auth_handoff",
                Some("installation_failed"),
            )),
            None,
            Some(native),
        )
        .unwrap();
        let payload: Value = serde_json::from_slice(&report.bytes).unwrap();
        assert!(payload["helper_log"]
            .as_str()
            .unwrap()
            .contains("not_installed"));
        let log = payload["application_log"].as_str().unwrap();
        assert!(log.contains("common.pre_auth_handoff"));
        assert!(log.contains("installation_failed"));
    }
}
