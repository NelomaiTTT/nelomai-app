# Windows-only script behavior tests. These functions replace every external
# Defender/registry operation; no actual AV policy or HKLM access is performed.
if ($env:OS -ne 'Windows_NT') { throw 'Run these fixtures on Windows PowerShell' }
$ErrorActionPreference = 'Stop'
$global:Owned = @{}
$global:Excluded = @()
$global:FailAdd = $false
function global:Test-Path { param($LiteralPath) return $global:Owned.Count -gt 0 }
function global:Get-ItemProperty { param($LiteralPath) return [pscustomobject]$global:Owned }
function global:New-Item { param($Path, [switch]$Force) }
function global:New-ItemProperty { param($LiteralPath, $Name, $PropertyType, $Value, [switch]$Force) $global:Owned[$Name] = $Value }
function global:Remove-ItemProperty { param($LiteralPath, $Name) $global:Owned.Remove($Name) }
function global:Get-MpPreference { return [pscustomobject]@{ ExclusionPath = $global:Excluded } }
function global:Add-MpPreference {
    param($ExclusionPath)
    if ($global:FailAdd) { throw 'Injected Add failure' }
    $global:Excluded += $ExclusionPath
}
function global:Remove-MpPreference {
    param($ExclusionPath)
    $global:Excluded = @($global:Excluded | Where-Object { $_ -ine $ExclusionPath })
}
function Assert($condition, [string]$message) { if (-not $condition) { throw $message } }
$scriptPath = Join-Path $PSScriptRoot '..\install\defender-exclusions.ps1'
$env:NELOMAI_DEFENDER_INSTALL_DIR = 'C:\Program Files\Nelomai'
$env:NELOMAI_DEFENDER_PRIVILEGED_DIR = 'C:\Program Files\Nelomai\privileged'
$source = $env:NELOMAI_DEFENDER_INSTALL_DIR + '\runtime\engines\latest\0.2.16\amneziawg-tunnel.dll'
$generation = ('a' * 64) + '-123abc'
$stage = $env:NELOMAI_DEFENDER_PRIVILEGED_DIR + '\releases\.stage-' + $generation + '\engines\latest\0.2.16\amneziawg-tunnel.dll'
$final = $stage.Replace('\.stage-', '\')
function Invoke-Fixture([string]$action, [string]$path = '') {
    $env:NELOMAI_DEFENDER_ACTION = $action
    $env:NELOMAI_DEFENDER_EXCLUSION_PATH = $path
    & $scriptPath
}

# Separate ownership, stage cleanup, then complete uninstall.
foreach ($path in @($source, $stage, $final)) { Invoke-Fixture 'add' $path }
Assert ($global:Owned.Count -eq 3) 'One path must not overwrite another ownership record'
Assert ($global:Excluded.Count -eq 3) 'Expected three exact file exceptions'
Invoke-Fixture 'remove' $stage
Assert ($global:Owned.Count -eq 2 -and $global:Excluded.Count -eq 2) 'Stage cleanup must retain source/final'
Invoke-Fixture 'cleanup'
Assert ($global:Owned.Count -eq 0 -and $global:Excluded.Count -eq 0) 'Full cleanup must remove owned paths'

# An already present user's exception must not become installer-owned.
$global:Excluded = @($source)
Invoke-Fixture 'add' $source
Assert ($global:Owned.Count -eq 0) 'Preexisting exception was claimed'
Invoke-Fixture 'cleanup'
Assert ($global:Excluded -contains $source) 'User exception was removed'
$global:Excluded = @()

# Failed/uncertain Add leaves its persisted intent cleanable after restart.
$global:FailAdd = $true
$failed = $false
try { Invoke-Fixture 'add' $source } catch { $failed = $true }
Assert ($failed -and $global:Owned.Count -eq 1) 'Add intent must precede its external effect'
$global:FailAdd = $false
Invoke-Fixture 'cleanup'
Assert ($global:Owned.Count -eq 0) 'Failed Add record remained after cleanup'

# Invalid roots/paths cannot reach any external Add; old valid ownership works.
foreach ($path in @('C:\Users\fixture\amneziawg-tunnel.dll', 'C:\Program Files\Nelomai', 'C:\Program Files\Nelomai\runtime\engines\latest\0.2.16\other.dll', '\\host\share\amneziawg-tunnel.dll')) {
    $failed = $false
    try { Invoke-Fixture 'add' $path } catch { $failed = $true }
    Assert ($failed -and $global:Owned.Count -eq 0 -and $global:Excluded.Count -eq 0) 'Invalid path reached Defender'
}
$legacy = 'C:\Program Files\Nelomai\amneziawg-tunnel.dll'
$global:Owned['ManagedDefenderExclusionPath'] = $legacy
$global:Owned['ManagedDefenderExclusionPathV1-invalid'] = 'C:\Users\fixture\amneziawg-tunnel.dll'
$global:Excluded = @($legacy, 'C:\Users\fixture\amneziawg-tunnel.dll')
Invoke-Fixture 'cleanup'
Assert ($global:Excluded.Count -eq 1 -and $global:Owned.Count -eq 1) 'Legacy cleanup must not widen its scope'
Write-Output 'PASS: exact-path ownership, stage cleanup, preexisting exception, interrupted Add, legacy/path rejection'
