param(
    [string]$FixtureRoot = $env:ProgramFiles,
    [string]$TestExecutable
)
$ErrorActionPreference = 'Stop'
# Private SYSTEM/Admin fixtures only: no product service, WFP, or shared ACL changes.
# Exclusive test namespace; other Admin/SYSTEM writers must not replace it during the run.
# Rust pins the complete non-reparse parent chain before atomic private creation.
# ProgramFiles allows public reads, not writes; ProgramData is not a safe creator parent.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Member file operation tests require an elevated Windows token'
}
if (-not (Test-Path -LiteralPath $FixtureRoot -PathType Container)) {
    throw 'An existing local fixture parent is required; no fallback'
}
$fixture = (Resolve-Path -LiteralPath $FixtureRoot).ProviderPath
$drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($fixture))
if ($drive.DriveType -ne [IO.DriveType]::Fixed) {
    throw 'Member file fixtures require a fixed local drive'
}
if ([string]::IsNullOrWhiteSpace($TestExecutable)) {
    $build = @(& cargo test --locked -p nelomai-windows-service --lib --no-run --message-format=json)
    if ($LASTEXITCODE -ne 0) { throw 'Member file test compilation failed' }
    $artifacts = @($build | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object {
        $_.reason -ceq 'compiler-artifact' -and $_.target.name -ceq 'nelomai_windows_service' -and $_.profile.test -and $_.executable
    })
    if ($artifacts.Count -ne 1) { throw 'Expected exactly one member file library test executable' }
    $TestExecutable = $artifacts[0].executable
}
$exe = (Resolve-Path -LiteralPath $TestExecutable).ProviderPath
function Invoke-MemberTests([string]$Arguments) {
    # Capture both pipes: a deliberately caught Rust unwind writes to stderr,
    # which Windows PowerShell 5 must not turn into an early script failure.
    $start = [Diagnostics.ProcessStartInfo]::new($exe)
    $start.Arguments = $Arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.EnvironmentVariables['NELOMAI_MEMBER_FILES_TEST_ROOT'] = $fixture
    $process = [Diagnostics.Process]::new()
    try {
        $process.StartInfo = $start
        if (-not $process.Start()) { throw 'Member file test process did not start' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) {
            $process.Kill()
            $process.WaitForExit()
            throw 'Own member file test process exceeded its bounded timeout'
        }
        return [pscustomobject]@{ Code = $process.ExitCode; Out = $stdout.Result; Err = $stderr.Result }
    } finally { $process.Dispose() }
}
$filter = 'windows::member_files::native::operation_tests::'
$expected = @(
    'operation_acl_drift_after_preflight_or_lock_denies_callback_and_releases_lock',
    'operation_callback_error_and_unwind_release_lock_and_recheck_on_retry',
    'operation_cold_init_and_cas_preserve_exact_bytes',
    'operation_existing_lock_acl_denies_callback_and_retries_after_restore',
    'operation_existing_nonempty_lock_denies_callback_and_retries_after_restore',
    'operation_fixture_parent_is_validated_before_creation',
    'operation_no_share_lock_rejects_contention_and_retries_after_release',
    'operation_postaction_acl_drift_denies_success_without_claiming_write_rollback',
    'operation_postaction_acl_drift_overrides_callback_error',
    'operation_preflight_acl_drift_denies_before_lock_open',
    'operation_warm_read_has_one_prelock_directory_pass'
) | ForEach-Object { $filter + $_ }
$list = Invoke-MemberTests "$filter --ignored --list"
if ($list.Code -ne 0) { throw 'Member file native inventory failed' }
$selected = @($list.Out -split '\r?\n' | Where-Object { $_ -cmatch ': test$' } | ForEach-Object { $_ -creplace ': test$', '' })
if ($selected.Count -ne $expected.Count -or @(Compare-Object -CaseSensitive $expected $selected).Count -ne 0) {
    throw 'Expected the complete exact member file native inventory; no empty/partial-filter PASS'
}
$run = Invoke-MemberTests "$filter --ignored --nocapture --test-threads=1"
Write-Output $run.Out
[Console]::Error.Write($run.Err)
if ($run.Code -ne 0) { throw "Member file native tests failed with exit $($run.Code)" }
if ($run.Out -cnotmatch ("(?m)^test result: ok\. " + $expected.Count + ' passed; 0 failed; 0 ignored;')) {
    throw 'Missing exact successful member file native execution count'
}
