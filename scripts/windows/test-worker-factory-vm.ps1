param(
    [Parameter(Mandatory = $true)][string]$ArtifactDirectory,
    [Parameter(Mandatory = $true)][string]$SourceSha,
    [Parameter(Mandatory = $true)][string]$ManifestSha256,
    [Parameter(Mandatory = $true)][Guid]$VmId,
    [Parameter(Mandatory = $true)][string]$VmName,
    [Parameter(Mandatory = $true)][Guid]$SnapshotId,
    [Parameter(Mandatory = $true)][string]$SnapshotName,
    [Parameter(Mandatory = $true)][string]$HostName,
    [Parameter(Mandatory = $true)][string]$CredentialFile,
    [Parameter(Mandatory = $true)][System.Net.IPAddress]$PeerAddress,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
# CI-only: a retained host peer child and one explicitly owned, initially OFF
# disposable VM. No runner registration, firewall changes or runtime fallback.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_EVENT_NAME -cne 'push' -or
    $env:GITHUB_REF -cne 'refs/heads/Future/windows-hot-standby-0.4.0') {
    throw 'Worker VM gate requires the trusted branch push aperture'
}
if ($env:COMPUTERNAME -cne $HostName -or $VmId -eq [Guid]::Empty -or $SnapshotId -eq [Guid]::Empty -or
    $PeerAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    [Net.IPAddress]::IsLoopback($PeerAddress)) { throw 'Worker host/VM/peer identity invalid' }
& python (Join-Path $PSScriptRoot 'carrier-factory-artifact.py') verify `
    --directory $ArtifactDirectory --source-sha $SourceSha --manifest-sha256 $ManifestSha256
if ($LASTEXITCODE -ne 0) { throw 'Current-source worker artifact verification failed' }
$artifact = (Resolve-Path -LiteralPath $ArtifactDirectory).Path
$manifest = Get-Content -LiteralPath (Join-Path $artifact 'manifest.json') -Raw | ConvertFrom-Json
$vm = Get-VM -Id $VmId
if ($vm.Name -cne $VmName -or $vm.State -ne 'Off') { throw 'Owned disposable VM must be OFF' }
$snapshots = @(Get-VMSnapshot -VM $vm | Where-Object { $_.Id -eq $SnapshotId })
if ($snapshots.Count -ne 1 -or $snapshots[0].Name -cne $SnapshotName) { throw 'Clean snapshot identity mismatch' }
$credential = Import-Clixml -LiteralPath $CredentialFile
$work = Join-Path $OutputDirectory ('worker-factory-vm-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$session = $null; $peer = $null; $peerStarted = $false; $started = $false; $ports = @(); $failure = $null
$result = [ordered]@{ source_sha = $SourceSha; manifest_sha256 = $ManifestSha256; vm_id = $VmId; passed = $false }
try {
    Restore-VMSnapshot -VMSnapshot $snapshots[0] -Confirm:$false
    Start-VM -VM $vm | Out-Null
    $started = $true
    $bootWatch = [Diagnostics.Stopwatch]::StartNew()
    while (-not $session -and $bootWatch.Elapsed.TotalSeconds -lt 90) {
        try { $session = New-PSSession -VMId $VmId -Credential $credential -ErrorAction Stop }
        catch { Start-Sleep -Seconds 2 }
    }
    if (-not $session) { throw 'Guest PowerShell Direct readiness deadline' }
    $guestDirectory = Invoke-Command -Session $session -ArgumentList $VmId, $VmName -ScriptBlock {
        param($id, $name)
        $ErrorActionPreference = 'Stop'
        $guest = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'
        if ([Guid]$guest.VirtualMachineId -ne $id -or $guest.VirtualMachineName -cne $name) { throw 'Guest identity mismatch' }
        if (Get-Process -Name factory-tests,nelomai-windows-worker -ErrorAction SilentlyContinue) { throw 'Existing native process' }
        if (Get-NetAdapter -IncludeHidden | Where-Object Name -like 'NeloWorker-*') { throw 'Existing worker adapter' }
        $dir = Join-Path 'C:\NelomaiNative' ('worker-ci-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $wfp = Join-Path $dir 'wfp-before.xml'
        & netsh wfp show state "file=$wfp" | Out-Null
        if ($LASTEXITCODE -ne 0 -or (Get-Content $wfp -Raw).Contains('Nelomai carrier guard v2')) { throw 'Existing or unknown guard state' }
        $dir
    }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $artifact 'worker-peers.exe'
    $info.Arguments = '-test.run=^$'
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $info.EnvironmentVariables['NELOMAI_WORKER_TEST_PEERS'] = $PeerAddress.ToString()
    $peer = [Diagnostics.Process]::new(); $peer.StartInfo = $info
    if (-not $peer.Start()) { throw 'Host peer child start failed' }
    $peerStarted = $true
    $ready = $peer.StandardOutput.ReadLineAsync()
    if (-not $ready.Wait(10000)) { throw 'Host peer readiness timeout' }
    $peers = $ready.Result | ConvertFrom-Json
    if ($peers.Count -ne 3 -or $peers[0].token -notmatch '^[a-f0-9]{32}$') { throw 'Malformed peer readiness' }
    foreach ($endpoint in @($peers[0].endpoint, $peers[1].endpoint, $peers[2].endpoint, $peers[0].control)) {
        if ($endpoint -notmatch ('^' + [regex]::Escape($PeerAddress.ToString()) + ':([0-9]+)$')) { throw 'Peer address mismatch' }
        $ports += [int]$Matches[1]
    }
    if (@($ports | Select-Object -Unique).Count -ne 4) { throw 'Peer ports not independent' }
    $readyFile = Join-Path $work 'peers.json'
    [IO.File]::WriteAllText($readyFile, $ready.Result, [Text.UTF8Encoding]::new($false))
    Copy-Item -LiteralPath $artifact -Destination (Join-Path $guestDirectory 'artifact') -Recurse -ToSession $session
    Copy-Item -LiteralPath $readyFile -Destination (Join-Path $guestDirectory 'peers.json') -ToSession $session
    # Clean Default Switch guests can expose PS Direct before DHCP/time settle.
    # Measure from this Start on the HOST; guest wall-clock changes cannot skip it.
    while ($true) {
        $currentVm = Get-VM -Id $VmId
        if ($currentVm.Id -ne $VmId -or $currentVm.Name -cne $VmName -or $currentVm.State -ne 'Running') {
            throw 'Owned VM identity/state changed during warm-up'
        }
        if ($bootWatch.Elapsed.TotalSeconds -ge 120) { throw 'Guest startup/warm-up deadline' }
        if ($peer.HasExited) { throw 'Host peer exited before native scenario' }
        if ($bootWatch.Elapsed.TotalSeconds -ge 80) { break }
        Start-Sleep -Seconds 1
    }
    $result.warmup_seconds = $bootWatch.Elapsed.TotalSeconds
    $result.native = Invoke-Command -Session $session -ArgumentList $guestDirectory, $manifest -ScriptBlock {
        param($dir, $manifest)
        $ErrorActionPreference = 'Stop'
        $artifact = Join-Path $dir 'artifact'
        foreach ($item in $manifest.files.PSObject.Properties) {
            if ((Get-FileHash -LiteralPath (Join-Path $artifact $item.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $item.Value) { throw 'Guest artifact byte mismatch' }
        }
        $exe = Join-Path $artifact 'factory-tests.exe'
        $selected = 'windows::member_worker_factory_native_tests::worker_factory_start_stop_fresh_child_repeat'
        $inventory = @(& $exe --exact $selected --ignored --list)
        if ($LASTEXITCODE -ne 0 -or @($inventory | Where-Object { $_ -ceq "${selected}: test" }).Count -ne 1) { throw 'Missing exact worker native test' }
        $env:NELOMAI_FACTORY_RUNTIME_DIRECTORY = Join-Path $artifact 'runtime'
        $env:NELOMAI_WORKER_PROOF_PEERS_JSON = Join-Path $dir 'peers.json'
        $out = Join-Path $dir 'stdout.log'; $err = Join-Path $dir 'stderr.log'
        $process = Start-Process -FilePath $exe -ArgumentList @('--exact', $selected, '--ignored', '--nocapture', '--test-threads=1') `
            -PassThru -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Hidden
        try {
            if (-not $process.WaitForExit(90000)) { $process.Kill(); [void]$process.WaitForExit(5000); throw 'Native worker scenario exceeded 90 seconds' }
            $output = [string](Get-Content -LiteralPath $out -Raw) + [string](Get-Content -LiteralPath $err -Raw)
            $worker = @(Get-CimInstance Win32_Process -Filter "Name='nelomai-windows-worker.exe'")
            $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object Name -like 'NeloWorker-*')
            $wfp = Join-Path $dir 'wfp-after.xml'
            & netsh wfp show state "file=$wfp" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Independent WFP inspection failed' }
            $guards = ([regex]::Matches((Get-Content $wfp -Raw), 'Nelomai carrier guard v2')).Count
            if ($process.ExitCode -ne 0 -or $output -notmatch '(?m)^test result: ok\. 1 passed; 0 failed;' -or
                $worker.Count -ne 0 -or $adapters.Count -ne 0 -or $guards -ne 0) { throw 'Worker native scenario or independent cleanup audit failed' }
            @{ exit_code = $process.ExitCode; worker_count = $worker.Count; adapter_count = $adapters.Count; guard_count = $guards }
        } finally { $process.Dispose() }
    }
    $result.passed = $true
} catch { $failure = $_; $result.error = $_.Exception.Message }
finally {
    if ($session) {
        foreach ($name in @('stdout.log', 'stderr.log', 'wfp-before.xml', 'wfp-after.xml')) {
            try { Copy-Item -LiteralPath (Join-Path $guestDirectory $name) -Destination (Join-Path $work $name) -FromSession $session -ErrorAction Stop }
            catch { $result["copy_$name"] = $_.Exception.Message }
        }
        Remove-PSSession $session -ErrorAction SilentlyContinue
    }
    if ($peerStarted) {
        try {
            try { $peer.StandardInput.Close() }
            finally {
                if (-not $peer.WaitForExit(5000)) { $peer.Kill(); [void]$peer.WaitForExit(5000) }
            }
            $result.peer_exit = $peer.ExitCode
            [IO.File]::WriteAllText((Join-Path $work 'peer-stderr.log'), $peer.StandardError.ReadToEnd())
            $remaining = @(Get-NetUDPEndpoint | Where-Object { $_.LocalPort -in $ports })
            $result.peer_ports_remaining = $remaining.Count
            if ($result.peer_exit -ne 0 -or $remaining.Count -ne 0) { $result.passed = $false }
        } catch { $result.passed = $false; $result.peer_cleanup_error = $_.Exception.Message }
        finally { $peer.Dispose() }
    } elseif ($peer) { $peer.Dispose() }
    if ($started) {
        $shutdown = $null
        try {
            $shutdown = Stop-VM -VM $vm -AsJob
            if (-not (Wait-Job -Job $shutdown -Timeout 45)) { throw 'Graceful VM shutdown deadline' }
            Receive-Job -Job $shutdown -ErrorAction Stop | Out-Null
            $result.vm_final_state = [string](Get-VM -Id $VmId).State
            if ($result.vm_final_state -cne 'Off') { $result.passed = $false }
        } catch { $result.passed = $false; $result.shutdown_error = $_.Exception.Message }
        finally {
            if ($shutdown) { Stop-Job -Job $shutdown -ErrorAction SilentlyContinue; Remove-Job -Job $shutdown -Force }
            $result.vm_final_state = [string](Get-VM -Id $VmId).State
        }
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $work 'result.json') -Encoding UTF8
}
if (-not $result.passed) { if ($failure) { throw $failure }; throw 'Worker native cleanup did not acknowledge completion' }
Get-Content -LiteralPath (Join-Path $work 'stdout.log') -Raw
Get-Content -LiteralPath (Join-Path $work 'stderr.log') -Raw
