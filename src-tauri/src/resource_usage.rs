use nelomai_client_api::{DiagnosticResourceComponent, DiagnosticResourceUsage};
use std::time::Instant;
use tauri::{AppHandle, Runtime};

pub struct ResourceSnapshot {
    captured_at: Instant,
    process: ProcessCounters,
    android_uid: Option<AndroidUidCounters>,
}

#[derive(Default)]
struct ProcessCounters {
    cpu_user_ms: Option<u64>,
    cpu_system_ms: Option<u64>,
    current_resident_memory_bytes: Option<u64>,
    peak_resident_memory_bytes: Option<u64>,
    read_bytes: Option<u64>,
    write_bytes: Option<u64>,
    page_faults: Option<u64>,
    minor_page_faults: Option<u64>,
    major_page_faults: Option<u64>,
    voluntary_context_switches: Option<u64>,
    involuntary_context_switches: Option<u64>,
}

#[derive(Default)]
struct AndroidUidCounters {
    cpu_user_ms: Option<u64>,
    cpu_system_ms: Option<u64>,
    network_rx_bytes: Option<u64>,
    network_tx_bytes: Option<u64>,
    cpu_charge_milliamp_milliseconds: Option<u64>,
    mobile_charge_milliamp_milliseconds: Option<u64>,
    wifi_charge_milliamp_milliseconds: Option<u64>,
}

impl ResourceSnapshot {
    pub fn capture<R: Runtime>(app: &AppHandle<R>) -> Self {
        #[cfg(target_os = "android")]
        let android_uid = capture_android_uid(app);
        #[cfg(not(target_os = "android"))]
        let android_uid = {
            let _ = app;
            None
        };

        Self {
            captured_at: Instant::now(),
            process: capture_process(),
            android_uid,
        }
    }

    #[cfg(test)]
    pub fn capture_for_test() -> Self {
        Self {
            captured_at: Instant::now(),
            process: capture_process(),
            android_uid: None,
        }
    }

    pub fn report(&self, current: Self) -> DiagnosticResourceUsage {
        let session_duration_ms = current
            .captured_at
            .saturating_duration_since(self.captured_at)
            .as_millis()
            .min(u64::MAX as u128) as u64;
        let mut components = vec![process_component(
            &self.process,
            &current.process,
            session_duration_ms,
        )];
        if let (Some(baseline), Some(current)) = (&self.android_uid, &current.android_uid) {
            components.push(android_uid_component(
                baseline,
                current,
                session_duration_ms,
            ));
        }

        DiagnosticResourceUsage {
            measurement_mode: "session_delta".to_string(),
            session_duration_ms,
            components,
        }
    }
}

fn process_component(
    baseline: &ProcessCounters,
    current: &ProcessCounters,
    duration_ms: u64,
) -> DiagnosticResourceComponent {
    let cpu_user_ms = delta(baseline.cpu_user_ms, current.cpu_user_ms);
    let cpu_system_ms = delta(baseline.cpu_system_ms, current.cpu_system_ms);
    DiagnosticResourceComponent {
        component: "client_process".to_string(),
        source: "operating_system_process_counters".to_string(),
        cpu_average_basis_points: average_cpu_basis_points(cpu_user_ms, cpu_system_ms, duration_ms),
        cpu_user_ms,
        cpu_system_ms,
        current_resident_memory_bytes: current.current_resident_memory_bytes,
        peak_resident_memory_bytes: current.peak_resident_memory_bytes,
        read_bytes: delta(baseline.read_bytes, current.read_bytes),
        write_bytes: delta(baseline.write_bytes, current.write_bytes),
        page_faults: delta(baseline.page_faults, current.page_faults),
        minor_page_faults: delta(baseline.minor_page_faults, current.minor_page_faults),
        major_page_faults: delta(baseline.major_page_faults, current.major_page_faults),
        voluntary_context_switches: delta(
            baseline.voluntary_context_switches,
            current.voluntary_context_switches,
        ),
        involuntary_context_switches: delta(
            baseline.involuntary_context_switches,
            current.involuntary_context_switches,
        ),
        network_rx_bytes: None,
        network_tx_bytes: None,
        cpu_charge_milliamp_milliseconds: None,
        mobile_charge_milliamp_milliseconds: None,
        wifi_charge_milliamp_milliseconds: None,
    }
}

fn android_uid_component(
    baseline: &AndroidUidCounters,
    current: &AndroidUidCounters,
    duration_ms: u64,
) -> DiagnosticResourceComponent {
    let cpu_user_ms = delta(baseline.cpu_user_ms, current.cpu_user_ms);
    let cpu_system_ms = delta(baseline.cpu_system_ms, current.cpu_system_ms);
    DiagnosticResourceComponent {
        component: "android_application_uid".to_string(),
        source: "android_system_health_manager".to_string(),
        cpu_average_basis_points: average_cpu_basis_points(cpu_user_ms, cpu_system_ms, duration_ms),
        cpu_user_ms,
        cpu_system_ms,
        current_resident_memory_bytes: None,
        peak_resident_memory_bytes: None,
        read_bytes: None,
        write_bytes: None,
        page_faults: None,
        minor_page_faults: None,
        major_page_faults: None,
        voluntary_context_switches: None,
        involuntary_context_switches: None,
        network_rx_bytes: delta(baseline.network_rx_bytes, current.network_rx_bytes),
        network_tx_bytes: delta(baseline.network_tx_bytes, current.network_tx_bytes),
        cpu_charge_milliamp_milliseconds: delta(
            baseline.cpu_charge_milliamp_milliseconds,
            current.cpu_charge_milliamp_milliseconds,
        ),
        mobile_charge_milliamp_milliseconds: delta(
            baseline.mobile_charge_milliamp_milliseconds,
            current.mobile_charge_milliamp_milliseconds,
        ),
        wifi_charge_milliamp_milliseconds: delta(
            baseline.wifi_charge_milliamp_milliseconds,
            current.wifi_charge_milliamp_milliseconds,
        ),
    }
}

fn delta(baseline: Option<u64>, current: Option<u64>) -> Option<u64> {
    current?.checked_sub(baseline?)
}

fn average_cpu_basis_points(
    user_ms: Option<u64>,
    system_ms: Option<u64>,
    duration_ms: u64,
) -> Option<u64> {
    let cpu_ms = user_ms?.saturating_add(system_ms?);
    if duration_ms == 0 {
        return None;
    }
    Some(cpu_ms.saturating_mul(10_000) / duration_ms)
}

#[cfg(unix)]
fn capture_process() -> ProcessCounters {
    let mut counters = ProcessCounters::default();
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } == 0 {
        let usage = unsafe { usage.assume_init() };
        counters.cpu_user_ms = timeval_millis(usage.ru_utime);
        counters.cpu_system_ms = timeval_millis(usage.ru_stime);
        counters.peak_resident_memory_bytes = peak_rss_bytes(usage.ru_maxrss);
        counters.minor_page_faults = nonnegative(usage.ru_minflt);
        counters.major_page_faults = nonnegative(usage.ru_majflt);
        counters.voluntary_context_switches = nonnegative(usage.ru_nvcsw);
        counters.involuntary_context_switches = nonnegative(usage.ru_nivcsw);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        counters.current_resident_memory_bytes = linux_current_rss_bytes();
        let (read_bytes, write_bytes) = linux_io_bytes();
        counters.read_bytes = read_bytes;
        counters.write_bytes = write_bytes;
    }
    #[cfg(target_os = "macos")]
    {
        counters.current_resident_memory_bytes = macos_current_rss_bytes();
    }
    counters
}

#[cfg(unix)]
fn timeval_millis(value: libc::timeval) -> Option<u64> {
    let seconds = u64::try_from(value.tv_sec).ok()?;
    let micros = u64::try_from(value.tv_usec).ok()?;
    Some(seconds.saturating_mul(1_000).saturating_add(micros / 1_000))
}

#[cfg(unix)]
fn nonnegative<T>(value: T) -> Option<u64>
where
    u64: TryFrom<T>,
{
    u64::try_from(value).ok()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peak_rss_bytes(value: libc::c_long) -> Option<u64> {
    nonnegative(value).map(|kibibytes| kibibytes.saturating_mul(1024))
}

#[cfg(target_os = "macos")]
fn peak_rss_bytes(value: libc::c_long) -> Option<u64> {
    nonnegative(value)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_current_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_proc_value(&status, "VmRSS:", 1024)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_io_bytes() -> (Option<u64>, Option<u64>) {
    let Ok(io) = std::fs::read_to_string("/proc/self/io") else {
        return (None, None);
    };
    (
        parse_proc_value(&io, "read_bytes:", 1),
        parse_proc_value(&io, "write_bytes:", 1),
    )
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_proc_value(contents: &str, key: &str, multiplier: u64) -> Option<u64> {
    contents.lines().find_map(|line| {
        let value = line.strip_prefix(key)?.split_whitespace().next()?;
        value
            .parse::<u64>()
            .ok()
            .map(|number| number.saturating_mul(multiplier))
    })
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn macos_current_rss_bytes() -> Option<u64> {
    let mut info = std::mem::MaybeUninit::<libc::mach_task_basic_info>::zeroed();
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
    let result = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            libc::MACH_TASK_BASIC_INFO,
            info.as_mut_ptr().cast(),
            &mut count,
        )
    };
    if result != libc::KERN_SUCCESS {
        return None;
    }
    Some(unsafe { info.assume_init() }.resident_size)
}

#[cfg(windows)]
fn capture_process() -> ProcessCounters {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetProcessIoCounters, GetProcessTimes, IO_COUNTERS,
    };

    let process = unsafe { GetCurrentProcess() };
    let mut counters = ProcessCounters::default();
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } != 0 {
        counters.cpu_user_ms = Some(filetime_millis(user));
        counters.cpu_system_ms = Some(filetime_millis(kernel));
    }

    let mut memory = PROCESS_MEMORY_COUNTERS::default();
    memory.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    if unsafe { GetProcessMemoryInfo(process, &mut memory, memory.cb) } != 0 {
        counters.current_resident_memory_bytes = Some(memory.WorkingSetSize as u64);
        counters.peak_resident_memory_bytes = Some(memory.PeakWorkingSetSize as u64);
        counters.page_faults = Some(memory.PageFaultCount as u64);
    }

    let mut io = IO_COUNTERS::default();
    if unsafe { GetProcessIoCounters(process, &mut io) } != 0 {
        counters.read_bytes = Some(io.ReadTransferCount);
        counters.write_bytes = Some(io.WriteTransferCount);
    }
    counters
}

#[cfg(windows)]
fn filetime_millis(value: windows_sys::Win32::Foundation::FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32 | value.dwLowDateTime as u64) / 10_000
}

#[cfg(target_os = "android")]
fn capture_android_uid<R: Runtime>(app: &AppHandle<R>) -> Option<AndroidUidCounters> {
    use tauri_plugin_tunnel_android::TunnelAndroidExt;

    let snapshot = app.tunnel_android().resource_usage().ok()?;
    Some(AndroidUidCounters {
        cpu_user_ms: snapshot.cpu_user_ms,
        cpu_system_ms: snapshot.cpu_system_ms,
        network_rx_bytes: snapshot.network_rx_bytes,
        network_tx_bytes: snapshot.network_tx_bytes,
        cpu_charge_milliamp_milliseconds: snapshot.cpu_charge_milliamp_milliseconds,
        mobile_charge_milliamp_milliseconds: snapshot.mobile_charge_milliamp_milliseconds,
        wifi_charge_milliamp_milliseconds: snapshot.wifi_charge_milliamp_milliseconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn report_uses_deltas_and_absolute_memory() {
        let baseline = ResourceSnapshot {
            captured_at: Instant::now(),
            process: ProcessCounters {
                cpu_user_ms: Some(10),
                cpu_system_ms: Some(5),
                current_resident_memory_bytes: Some(100),
                read_bytes: Some(1_000),
                ..ProcessCounters::default()
            },
            android_uid: None,
        };
        let current = ResourceSnapshot {
            captured_at: baseline.captured_at + Duration::from_secs(2),
            process: ProcessCounters {
                cpu_user_ms: Some(30),
                cpu_system_ms: Some(15),
                current_resident_memory_bytes: Some(250),
                read_bytes: Some(1_500),
                ..ProcessCounters::default()
            },
            android_uid: None,
        };

        let report = baseline.report(current);

        assert_eq!(report.session_duration_ms, 2_000);
        assert_eq!(report.components[0].cpu_user_ms, Some(20));
        assert_eq!(report.components[0].cpu_average_basis_points, Some(150));
        assert_eq!(
            report.components[0].current_resident_memory_bytes,
            Some(250)
        );
        assert_eq!(report.components[0].read_bytes, Some(500));
    }

    #[test]
    fn reset_counter_is_reported_as_unavailable() {
        assert_eq!(delta(Some(10), Some(5)), None);
    }
}
