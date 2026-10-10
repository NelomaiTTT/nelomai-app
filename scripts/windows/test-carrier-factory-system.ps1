param(
    [Parameter(Mandatory = $true)][string]$TestExecutable,
    [Parameter(Mandatory = $true)][string]$RuntimeDirectory,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Case,
    [Guid]$DisposableVmId = [Guid]::Empty
)
$ErrorActionPreference = 'Stop'
# This harness belongs only to disposable native CI or the explicit disposable VM, never line H.
# Production's unimpersonated SYSTEM gate and actual namespace/mutex calls stay
# intact. The ordinary suite runs separately; this executes its SAME factory test.
if ($env:GITHUB_ACTIONS -ne 'true') {
    if ($DisposableVmId -eq [Guid]::Empty) { throw 'Factory SYSTEM harness requires an explicit disposable VM ID outside GitHub Actions' }
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $guest = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'
    if ($computer.Name -cne 'NELOMAI033' -or $computer.Manufacturer -cne 'Microsoft Corporation' -or
        $computer.Model -cne 'Virtual Machine' -or $guest.VirtualMachineName -cne 'Nelomai-033-Native' -or
        [Guid]$guest.VirtualMachineId -ne $DisposableVmId) {
        throw 'Factory SYSTEM harness disposable guest identity mismatch'
    }
}
$selectedTest = 'windows::member_carrier_factory::actual_execution::carrier_factory_selects_new_path_for_supported_pair'
$exe = (Resolve-Path -LiteralPath $TestExecutable).Path
$selection = @(& $exe --exact $selectedTest --list)
if ($LASTEXITCODE -ne 0) { throw 'Factory test inventory failed' }
if (@($selection | Where-Object { $_ -eq "${selectedTest}: test" }).Count -ne 1) {
    throw 'Expected exactly one actual factory test; no empty-filter PASS'
}
$nonce = [Guid]::NewGuid().ToString('N')
$work = Join-Path $OutputDirectory "carrier-factory-system-$nonce"
New-Item -ItemType Directory -Path $work | Out-Null
& icacls.exe $work /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot protect own factory output directory' }
$log = Join-Path $work 'factory.log'
$resultPath = Join-Path $work 'result.json'
$payload = @{
    executable = $exe
    test = $selectedTest
    directory = (Get-Location).Path
    runtime = (Resolve-Path -LiteralPath $RuntimeDirectory).Path
    log = $log
    result = $resultPath
    case = $Case
} | ConvertTo-Json -Compress
$payload64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
# Encode data separately; no path/config interpolation into executable code.
$worker = @'
$ErrorActionPreference = 'Stop'
$data = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__')) | ConvertFrom-Json
$code = 1
$system = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $system = $identity.User.Value -eq 'S-1-5-18'
    if (-not $system) { throw 'Actual factory process is not SYSTEM' }
    Set-Location -LiteralPath $data.directory
    $env:NELOMAI_FACTORY_RUNTIME_DIRECTORY = $data.runtime
    $env:NELOMAI_FACTORY_SYSTEM_CASE = $data.case
    # PowerShell 5 treats native stderr as ErrorRecords. Capture both streams
    # directly so a normal Rust diagnostic cannot interrupt the actual test.
    $process = Start-Process -FilePath $data.executable -ArgumentList @(
        '--exact', $data.test, '--nocapture', '--test-threads=1'
    ) -WorkingDirectory $data.directory -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput ($data.log + '.stdout') -RedirectStandardError ($data.log + '.stderr')
    $code = $process.ExitCode
    $output = [string](Get-Content -LiteralPath ($data.log + '.stdout') -Raw) +
        [string](Get-Content -LiteralPath ($data.log + '.stderr') -Raw)
    [IO.File]::WriteAllText($data.log, $output)
} catch {
    $_ | Out-String | Out-File -LiteralPath $data.log -Encoding utf8 -Append
} finally {
    @{ exit_code = $code; system = $system } | ConvertTo-Json -Compress |
        Out-File -LiteralPath ($data.result + '.tmp') -Encoding utf8
    Move-Item -LiteralPath ($data.result + '.tmp') -Destination $data.result
}
exit $code
'@
$worker = $worker.Replace('__PAYLOAD__', $payload64)
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($worker))
$powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell/v1.0/powershell.exe'
$action = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 50)
$taskName = "NelomaiFactory-$nonce"
$registered = $false
$trace = $null
try {
    # TEMPORARY CI-only evidence; remove after the exact-MIB cause is known.
    if ($Case -ceq 'primary' -and $env:GITHUB_ACTIONS -eq 'true') {
        $nativeLastExit = $LASTEXITCODE
        $traceName = "NelomaiFactoryEtw-$nonce"
        $providers = Join-Path $work 'etw-providers.txt'; $etl = Join-Path $work 'etw-kernel.etl'
        $summary = Join-Path $work 'etw-summary.txt'
        $trace = [ordered]@{
            session = $traceName; source_sha = $env:SOURCE_SHA; native_case = $Case
            started_utc = [DateTime]::UtcNow.ToString('o'); format = 'bin'; max_mb = 128
            start_exit = $null; query_exit = $null; stop_exit = $null; summary_exit = $null
            etl_bytes = $null; limit_reached = $null; events_lost = $null; loss_report = $null
        }
        try {
            [IO.File]::WriteAllLines($providers, @('{cdead503-17f5-4a3e-b7ae-df8cc2902eb9} 0x415a 5', '{2f07e2ee-15db-40f1-90ef-9d7ba282188a} 0x19 5'), [Text.Encoding]::ASCII)
            & logman.exe create trace $traceName -o $etl -f bin -max 128 -bs 64 -nb 16 64 -pf $providers -ets *> (Join-Path $work 'etw-start.log')
            $trace.start_exit = $LASTEXITCODE
        } catch { $trace.start_error = $_ | Out-String }
        finally { $global:LASTEXITCODE = $nativeLastExit }
    }
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    $registered = $true
    $started = [DateTime]::UtcNow
    Start-ScheduledTask -TaskName $taskName
    $deadline = [DateTime]::UtcNow.AddMinutes(49)
    while (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Factory SYSTEM process exceeded CI aperture; no cleanup ACK' }
        $task = Get-ScheduledTask -TaskName $taskName
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        if ($task.State -eq 'Ready' -and $info.LastRunTime.ToUniversalTime() -ge $started.AddSeconds(-2) -and
            -not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
            throw "Factory SYSTEM process ended without its result, task exit $($info.LastTaskResult); no PASS"
        }
        Start-Sleep -Seconds 2
    }
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    $output = Get-Content -LiteralPath $log -Raw
    Write-Output $output
    if ($result.system -ne $true -or $result.exit_code -ne 0) { throw 'Actual SYSTEM factory scenario failed' }
    if ($output -notmatch '(?m)^test result: ok\. 1 passed; 0 failed;') {
        throw 'Missing exact factory execution count; no empty-filter PASS'
    }
    $expectedCompleted = if ($Case -in @('resolver-reference-error', 'resolver-reference-unwind')) { 3 } else { 1 }
    if ($output -notmatch ('(?m)^actual native factory coverage case=' + [regex]::Escape($Case) + ' completed=' + $expectedCompleted + '\r?$')) {
        throw 'Missing exact selected factory case completion; no partial-matrix PASS'
    }
} finally {
    try {
        if ($registered) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
    } finally {
        if ($null -ne $trace) {
            $nativeLastExit = $LASTEXITCODE
            try {
                & logman.exe query $traceName -ets *> (Join-Path $work 'etw-query.log')
                $trace.query_exit = $LASTEXITCODE
            } catch { $trace.query_error = $_ | Out-String }
            $trace.stop_attempt_utc = [DateTime]::UtcNow.ToString('o')
            try {
                & logman.exe stop $traceName -ets *> (Join-Path $work 'etw-stop.log')
                $trace.stop_exit = $LASTEXITCODE
            } catch { $trace.stop_error = $_ | Out-String }
            try {
                if (Test-Path -LiteralPath $etl -PathType Leaf) {
                    $trace.etl_bytes = (Get-Item -LiteralPath $etl).Length
                    & tracerpt.exe $etl -o NUL -summary $summary -y *> (Join-Path $work 'etw-decode.log')
                    $trace.summary_exit = $LASTEXITCODE
                    if (Test-Path -LiteralPath $summary -PathType Leaf) { $trace.loss_report = 'etw-summary.txt' }
                }
                if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
                    $trace.native_result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
                }
            } catch { $trace.summary_error = $_ | Out-String }
            $trace.finished_utc = [DateTime]::UtcNow.ToString('o')
            try {
                $trace | ConvertTo-Json -Depth 5 | Out-File -LiteralPath (Join-Path $work 'etw-result.json') -Encoding utf8
            } catch { Write-Warning "ETW evidence write failed: $_" -WarningAction Continue }
            $global:LASTEXITCODE = $nativeLastExit
        }
    }
}
