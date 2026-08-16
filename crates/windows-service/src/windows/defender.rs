use super::install::validate_install_location;
use crate::{
    AntivirusProduct, AntivirusProductState, DefenderExclusionState, DefenderStatus, ServiceError,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use std::os::windows::process::CommandExt;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::SecurityCenter::{
    IWSCProductList, WSCProductList, WSC_SECURITY_PRODUCT_OUT_OF_DATE,
    WSC_SECURITY_PRODUCT_STATE_EXPIRED, WSC_SECURITY_PRODUCT_STATE_OFF,
    WSC_SECURITY_PRODUCT_STATE_ON, WSC_SECURITY_PRODUCT_STATE_SNOOZED,
    WSC_SECURITY_PRODUCT_UP_TO_DATE, WSC_SECURITY_PROVIDER_ANTIVIRUS,
};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

const AWG_DLL_NAME: &str = "amneziawg-tunnel.dll";
const CHECK_TIMEOUT: Duration = Duration::from_secs(8);
const REPAIR_TIMEOUT: Duration = Duration::from_secs(30);
const DEFENDER_ACTIVE_SCRIPT: &str = "$ErrorActionPreference=[Management.Automation.ActionPreference]::Stop; $status=Get-MpComputerStatus -ErrorAction Stop; if($status.AntivirusEnabled -and $status.RealTimeProtectionEnabled -and $status.AMRunningMode -ne 'Passive Mode'){exit 0}; exit 20";
const ADD_EXCLUSION_SCRIPT: &str = r"$ErrorActionPreference=[Management.Automation.ActionPreference]::Stop; $path=$env:NELOMAI_DEFENDER_EXCLUSION_PATH; if([string]::IsNullOrWhiteSpace($path)){exit 30}; $existing=@((Get-MpPreference -ErrorAction Stop).ExclusionPath); if($existing -notcontains $path){Add-MpPreference -ExclusionPath $path -ErrorAction Stop}; New-Item -Path 'HKLM:\SOFTWARE\Nelomai\Client' -Force -ErrorAction Stop | Out-Null; New-ItemProperty -Path 'HKLM:\SOFTWARE\Nelomai\Client' -Name 'ManagedDefenderExclusionPath' -PropertyType String -Value $path -Force -ErrorAction Stop | Out-Null";

pub(crate) fn exclusion_status() -> DefenderStatus {
    let (antivirus_products, antivirus_detail_code) = antivirus_products();
    let dll_path = match std::env::current_exe() {
        Ok(path) => path.with_file_name(AWG_DLL_NAME),
        Err(_) => {
            return status(
                DefenderExclusionState::Unavailable,
                false,
                Some("service_path_unavailable"),
                antivirus_products,
                antivirus_detail_code,
            );
        }
    };
    let dll_present = dll_path.is_file();
    let Some(checker) = mpcmdrun_path() else {
        return status(
            DefenderExclusionState::Unavailable,
            dll_present,
            Some("defender_checker_unavailable"),
            antivirus_products,
            antivirus_detail_code,
        );
    };
    let mut command = Command::new(checker);
    command.args(["-CheckExclusion", "-Path"]).arg(&dll_path);
    match run_hidden(&mut command, CHECK_TIMEOUT) {
        CommandResult::Exit(0) => {
            return status(
                DefenderExclusionState::Excluded,
                dll_present,
                None,
                antivirus_products,
                antivirus_detail_code,
            );
        }
        CommandResult::Exit(1) => {}
        CommandResult::Exit(_) => {
            return status(
                DefenderExclusionState::Unavailable,
                dll_present,
                Some("defender_check_failed"),
                antivirus_products,
                antivirus_detail_code,
            );
        }
        CommandResult::Timeout => {
            return status(
                DefenderExclusionState::Unavailable,
                dll_present,
                Some("defender_check_timeout"),
                antivirus_products,
                antivirus_detail_code,
            );
        }
        CommandResult::SpawnFailed => {
            return status(
                DefenderExclusionState::Unavailable,
                dll_present,
                Some("defender_checker_unavailable"),
                antivirus_products,
                antivirus_detail_code,
            );
        }
    }

    match defender_active() {
        CommandResult::Exit(0) => status(
            DefenderExclusionState::Missing,
            dll_present,
            None,
            antivirus_products,
            antivirus_detail_code,
        ),
        CommandResult::Exit(20) => status(
            DefenderExclusionState::Inactive,
            dll_present,
            None,
            antivirus_products,
            antivirus_detail_code,
        ),
        CommandResult::Exit(_) => status(
            DefenderExclusionState::Unavailable,
            dll_present,
            Some("defender_status_failed"),
            antivirus_products,
            antivirus_detail_code,
        ),
        CommandResult::Timeout => status(
            DefenderExclusionState::Unavailable,
            dll_present,
            Some("defender_status_timeout"),
            antivirus_products,
            antivirus_detail_code,
        ),
        CommandResult::SpawnFailed => status(
            DefenderExclusionState::Unavailable,
            dll_present,
            Some("defender_status_unavailable"),
            antivirus_products,
            antivirus_detail_code,
        ),
    }
}

pub fn configure_exclusion(client_executable: &Path) -> Result<(), ServiceError> {
    let service_executable = std::env::current_exe()
        .map_err(|error| ServiceError::Backend(format!("resolve service executable: {error}")))?;
    let client_executable = validate_install_location(&service_executable, client_executable)?;
    let dll_path = client_executable.with_file_name(AWG_DLL_NAME);
    let powershell = powershell_path()
        .ok_or_else(|| ServiceError::Backend("defender_repair_tool_unavailable".to_string()))?;
    let mut command = Command::new(powershell);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            ADD_EXCLUSION_SCRIPT,
        ])
        .env("NELOMAI_DEFENDER_EXCLUSION_PATH", &dll_path);
    match run_hidden(&mut command, REPAIR_TIMEOUT) {
        CommandResult::Exit(0) => Ok(()),
        CommandResult::Exit(_) => Err(ServiceError::Backend(
            "defender_exclusion_repair_failed".to_string(),
        )),
        CommandResult::Timeout => Err(ServiceError::Backend(
            "defender_exclusion_repair_timeout".to_string(),
        )),
        CommandResult::SpawnFailed => Err(ServiceError::Backend(
            "defender_repair_tool_unavailable".to_string(),
        )),
    }
}

fn defender_active() -> CommandResult {
    let Some(powershell) = powershell_path() else {
        return CommandResult::SpawnFailed;
    };
    let mut command = Command::new(powershell);
    command.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        DEFENDER_ACTIVE_SCRIPT,
    ]);
    run_hidden(&mut command, CHECK_TIMEOUT)
}

fn powershell_path() -> Option<PathBuf> {
    let root = std::env::var_os("SystemRoot")?;
    let path = PathBuf::from(root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    path.is_file().then_some(path)
}

fn mpcmdrun_path() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(program_data) = std::env::var_os("ProgramData") {
        let platform = PathBuf::from(program_data)
            .join("Microsoft")
            .join("Windows Defender")
            .join("Platform");
        if let Ok(entries) = std::fs::read_dir(platform) {
            for entry in entries.flatten() {
                let candidate = entry.path().join("MpCmdRun.exe");
                if candidate.is_file() {
                    candidates.push(candidate);
                }
            }
        }
    }
    candidates.sort_by(|left, right| left.parent().cmp(&right.parent()));
    if let Some(candidate) = candidates.pop() {
        return Some(candidate);
    }
    let program_files = std::env::var_os("ProgramFiles")?;
    let fallback = PathBuf::from(program_files)
        .join("Windows Defender")
        .join("MpCmdRun.exe");
    fallback.is_file().then_some(fallback)
}

fn status(
    state: DefenderExclusionState,
    dll_present: bool,
    detail_code: Option<&str>,
    antivirus_products: Vec<AntivirusProduct>,
    antivirus_detail_code: Option<String>,
) -> DefenderStatus {
    DefenderStatus {
        state,
        dll_present,
        detail_code: detail_code.map(str::to_string),
        antivirus_products,
        antivirus_detail_code,
    }
}

fn antivirus_products() -> (Vec<AntivirusProduct>, Option<String>) {
    match query_antivirus_products() {
        Ok(products) => (products, None),
        Err(()) => (Vec::new(), Some("security_center_unavailable".to_string())),
    }
}

fn query_antivirus_products() -> Result<Vec<AntivirusProduct>, ()> {
    // SAFETY: the COM apartment is initialized for this request thread, every returned
    // interface is owned by the generated Windows bindings, and the guard balances only
    // successful CoInitializeEx calls.
    unsafe {
        let initialized = CoInitializeEx(None, COINIT_MULTITHREADED);
        if initialized.is_err() {
            return Err(());
        }
        let _guard = ComApartment;
        let list: IWSCProductList =
            CoCreateInstance(&WSCProductList, None, CLSCTX_INPROC_SERVER).map_err(|_| ())?;
        list.Initialize(WSC_SECURITY_PROVIDER_ANTIVIRUS)
            .map_err(|_| ())?;
        let count = list.Count().map_err(|_| ())?.max(0) as u32;
        let mut products = Vec::with_capacity(count.min(8) as usize);
        for index in 0..count.min(8) {
            let Ok(product) = list.get_Item(index) else {
                continue;
            };
            let Ok(name) = product.ProductName() else {
                continue;
            };
            let name = normalized_product_name(&name.to_string());
            if name.is_empty() {
                continue;
            }
            let state = product
                .ProductState()
                .map(antivirus_product_state)
                .unwrap_or(AntivirusProductState::Unknown);
            let signatures_up_to_date = product.SignatureStatus().ok().and_then(|status| {
                if status == WSC_SECURITY_PRODUCT_UP_TO_DATE {
                    Some(true)
                } else if status == WSC_SECURITY_PRODUCT_OUT_OF_DATE {
                    Some(false)
                } else {
                    None
                }
            });
            let is_default = product.ProductIsDefault().ok().map(|value| value.as_bool());
            products.push(AntivirusProduct {
                is_microsoft_defender: is_microsoft_defender_name(&name),
                name,
                state,
                signatures_up_to_date,
                is_default,
            });
        }
        products.sort_by(|left, right| left.name.cmp(&right.name));
        products.dedup_by(|left, right| left.name.eq_ignore_ascii_case(&right.name));
        Ok(products)
    }
}

fn antivirus_product_state(
    state: windows::Win32::System::SecurityCenter::WSC_SECURITY_PRODUCT_STATE,
) -> AntivirusProductState {
    if state == WSC_SECURITY_PRODUCT_STATE_ON {
        AntivirusProductState::On
    } else if state == WSC_SECURITY_PRODUCT_STATE_OFF {
        AntivirusProductState::Off
    } else if state == WSC_SECURITY_PRODUCT_STATE_SNOOZED {
        AntivirusProductState::Snoozed
    } else if state == WSC_SECURITY_PRODUCT_STATE_EXPIRED {
        AntivirusProductState::Expired
    } else {
        AntivirusProductState::Unknown
    }
}

fn normalized_product_name(name: &str) -> String {
    name.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(120)
        .collect()
}

fn is_microsoft_defender_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("microsoft defender") || name.contains("windows defender")
}

struct ComApartment;

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: this guard is constructed only after CoInitializeEx succeeds on this thread.
        unsafe { CoUninitialize() };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandResult {
    Exit(i32),
    Timeout,
    SpawnFailed,
}

fn run_hidden(command: &mut Command, timeout: Duration) -> CommandResult {
    command
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut child) = command.spawn() else {
        return CommandResult::SpawnFailed;
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return CommandResult::Exit(status.code().unwrap_or(-1)),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return CommandResult::Timeout;
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return CommandResult::SpawnFailed;
            }
        }
    }
}
