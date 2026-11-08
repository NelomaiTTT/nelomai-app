# Windows-only script behavior tests. These functions replace every external
# Defender/registry operation; no actual AV policy or HKLM access is performed.
if ($env:OS -ne 'Windows_NT') { throw 'Run these fixtures on Windows PowerShell' }
$ErrorActionPreference = 'Stop'
$global:Owned = @{}
$global:Excluded = @()
$global:FailAdd = $false
$global:FailRemove = $false
$global:KeyExists = $false
$global:ParentExists = $false
$global:ParentValues = @{}
$global:FailCreateClient = $false
$global:AddCalls = 0
$global:Removed = @()
$global:Effective = @()
function global:Test-Path {
    param($LiteralPath)
    if ($LiteralPath -ieq 'HKLM:\SOFTWARE\Nelomai') { return $global:ParentExists }
    if ($LiteralPath -ieq 'HKLM:\SOFTWARE\Nelomai\Client') { return $global:KeyExists }
    throw 'Unexpected registry path'
}
function global:Get-ItemProperty { param($LiteralPath) return [pscustomobject]$global:Owned }
function global:New-Item {
    param($Path, [switch]$Force)
    if ($Path -ieq 'HKLM:\SOFTWARE\Nelomai') {
        if ($global:ParentExists) {
            if (-not $Force) { throw 'Parent already exists' }
            $global:ParentValues.Clear()
            $global:KeyExists = $false
            $global:Owned.Clear()
        }
        $global:ParentExists = $true
        return
    }
    if ($Path -ine 'HKLM:\SOFTWARE\Nelomai\Client') { throw 'Unexpected creation path' }
    if (-not $global:ParentExists) {
        if (-not $Force) { throw 'Registry parent missing' }
        $global:ParentExists = $true
    }
    if ($global:FailCreateClient) { throw 'Injected Client creation failure' }
    # Registry New-Item -Force replaces an existing key and its values.
    if ($global:KeyExists) {
        if (-not $Force) { throw 'Key already exists' }
        $global:Owned.Clear()
    }
    $global:KeyExists = $true
}
function global:New-ItemProperty { param($LiteralPath, $Name, $PropertyType, $Value, [switch]$Force) $global:Owned[$Name] = $Value }
function global:Remove-ItemProperty { param($LiteralPath, $Name) $global:Owned.Remove($Name) }
function global:Get-MpPreference { return [pscustomobject]@{ ExclusionPath = $global:Excluded } }
function global:Add-MpPreference {
    param($ExclusionPath)
    $global:AddCalls++
    if ($global:FailAdd) { throw 'Injected Add failure' }
    if ($global:Excluded -inotcontains $ExclusionPath) {
        $global:Excluded += $ExclusionPath
        $global:Effective = @($global:Excluded)
    }
}
function global:Remove-MpPreference {
    param($ExclusionPath)
    $global:Removed += $ExclusionPath
    if ($global:FailRemove) { throw 'Injected Remove failure' }
    $global:Excluded = @($global:Excluded | Where-Object { $_ -ine $ExclusionPath })
    $global:Effective = @($global:Excluded)
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

# Clean machine: create manufacturer + Client before durable intent/Add.
Invoke-Fixture 'add' $source
Assert ($global:ParentExists -and $global:KeyExists -and $global:Owned.Count -eq 1 -and $global:Excluded.Count -eq 1) 'Fresh registry hierarchy was not created before exclusion'
Invoke-Fixture 'cleanup'

# Existing parent must retain its values when only Client is missing.
$global:KeyExists = $false
$global:ParentValues['KeepParent'] = 'keep'
Invoke-Fixture 'add' $source
Assert ($global:ParentValues['KeepParent'] -eq 'keep' -and $global:Owned.Count -eq 1) 'Creating Client replaced its parent'
Invoke-Fixture 'cleanup'

# Interrupted creation after the parent: no intent/effect, retry preserves it.
$global:ParentExists = $false
$global:KeyExists = $false
$global:ParentValues = @{}
$global:FailCreateClient = $true
$beforeAdd = $global:AddCalls
$failed = $false
try { Invoke-Fixture 'add' $source } catch { $failed = $true }
Assert ($failed -and $global:ParentExists -and -not $global:KeyExists -and $global:Owned.Count -eq 0 -and $global:AddCalls -eq $beforeAdd) 'Partial key creation applied an exclusion or lost parent'
$global:ParentValues['KeepParent'] = 'keep'
$global:FailCreateClient = $false
Invoke-Fixture 'add' $source
Assert ($global:ParentValues['KeepParent'] -eq 'keep' -and $global:KeyExists -and $global:Owned.Count -eq 1) 'Retry did not complete parent-only creation'
Invoke-Fixture 'cleanup'

# Separate ownership, stage cleanup, then complete uninstall.
foreach ($path in @($source, $stage, $final)) { Invoke-Fixture 'add' $path }
Assert ($global:Owned.Count -eq 3) 'One path must not overwrite another ownership record'
Assert ($global:Excluded.Count -eq 3) 'Expected three exact file exceptions'
Invoke-Fixture 'remove' $stage
Assert ($global:Owned.Count -eq 2 -and $global:Excluded.Count -eq 2) 'Stage cleanup must retain source/final'
Invoke-Fixture 'cleanup'
Assert ($global:Owned.Count -eq 0 -and $global:Excluded.Count -eq 0) 'Full cleanup must remove owned paths'

# The verified broker uses a canonical extended local path; copying/repair must
# own the same exact DLL paths as the ordinary NSIS representation.
$plainInstallDir = $env:NELOMAI_DEFENDER_INSTALL_DIR
$plainPrivilegedDir = $env:NELOMAI_DEFENDER_PRIVILEGED_DIR
$currentPaths = @($source, $stage, $final) | ForEach-Object { $_.Replace('0.2.16', '0.4.1') }
foreach ($path in $currentPaths) { Invoke-Fixture 'add' $path }
$ownershipNames = @($global:Owned.Keys | Sort-Object) -join ','
try {
    $env:NELOMAI_DEFENDER_INSTALL_DIR = '\\?\' + $plainInstallDir
    foreach ($path in $currentPaths) { Invoke-Fixture 'add' $path }
    $env:NELOMAI_DEFENDER_PRIVILEGED_DIR = '\\?\' + $plainPrivilegedDir
    foreach ($path in $currentPaths) { Invoke-Fixture 'add' ('\\?\' + $path) }
    Assert ($global:Owned.Count -eq 3 -and $global:Excluded.Count -eq 3) 'Canonical paths must not duplicate exact exceptions'
    Assert ((@($global:Owned.Keys | Sort-Object) -join ',') -eq $ownershipNames) 'Canonical paths must retain the same ownership names'
    foreach ($path in $currentPaths) {
        Assert ($global:Excluded -contains $path) 'Store the same ordinary exact path for Defender'
        Invoke-Fixture 'remove' ('\\?\' + $path)
    }
    Assert ($global:Owned.Count -eq 0 -and $global:Excluded.Count -eq 0) 'Canonical removal must clean the same owned paths'
} finally {
    $env:NELOMAI_DEFENDER_INSTALL_DIR = $plainInstallDir
    $env:NELOMAI_DEFENDER_PRIVILEGED_DIR = $plainPrivilegedDir
}

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


# Configured membership alone is not an effective exclusion. Explicit repair
# refreshes only this app's exact owned path and preserves all ownership values.
$global:Owned = @{ UnrelatedSetting = 'keep' }
$global:KeyExists = $true
$global:Excluded = @()
foreach ($path in @($source, $final)) { Invoke-Fixture 'add' $path }
Assert ($global:Owned['UnrelatedSetting'] -eq 'keep') 'Adding a path erased unrelated settings'
$global:Effective = @()
$beforeRemove = $global:Removed.Count
Invoke-Fixture 'repair' $final
Assert ($global:Effective -contains $final) 'Repair did not activate an already configured exclusion'
Assert ($global:Removed.Count -eq $beforeRemove + 1 -and $global:Removed[-1] -eq $final) 'Repair touched another path'
Assert ($global:Excluded.Count -eq 2 -and $global:Owned.Count -eq 3) 'Repair lost another exclusion or ownership record'
Invoke-Fixture 'repair' ('\\?\' + $final)
Assert ($global:Excluded.Count -eq 2 -and $global:Owned.Count -eq 3) 'Repeated canonical repair changed ownership'

# A failed remove still attempts to restore the exact exception; a failed Add
# retains intent so a later invocation can complete it without losing siblings.
$global:FailRemove = $true
$beforeAdd = $global:AddCalls
$failed = $false
try { Invoke-Fixture 'repair' $final } catch { $failed = $true }
Assert ($failed -and $global:AddCalls -eq $beforeAdd + 1) 'Failed Remove did not retain its error and attempt restoration'
Assert ($global:Excluded -contains $final) 'Failed Remove lost the original exclusion'
$global:FailRemove = $false
$global:FailAdd = $true
$failed = $false
try { Invoke-Fixture 'repair' $final } catch { $failed = $true }
Assert ($failed -and $global:Owned.Count -eq 3 -and $global:Excluded -contains $source) 'Failed repair lost durable intent or another path'
$global:FailAdd = $false
Invoke-Fixture 'repair' $final
Assert ($global:Excluded.Count -eq 2 -and $global:Owned.Count -eq 3) 'Interrupted repair did not resume'
Invoke-Fixture 'cleanup'
Assert ($global:Owned.Count -eq 1 -and $global:Owned['UnrelatedSetting'] -eq 'keep') 'Cleanup removed unrelated settings'
$global:Owned = @{}

# Explicit repair cannot remove, re-add or claim a user's existing exclusion.
$global:Excluded = @($source)
$beforeAdd = $global:AddCalls
$beforeRemove = $global:Removed.Count
Invoke-Fixture 'repair' $source
Assert ($global:AddCalls -eq $beforeAdd -and $global:Removed.Count -eq $beforeRemove -and $global:Owned.Count -eq 0) 'Repair changed or claimed an unowned exception'
$global:Excluded = @()

# Invalid roots/paths cannot reach any external Add; old valid ownership works.
foreach ($path in @('C:\Users\fixture\amneziawg-tunnel.dll', 'C:\Program Files\Nelomai', 'C:\Program Files\Nelomai\runtime\engines\latest\0.2.16\other.dll', '\\host\share\amneziawg-tunnel.dll', '\\?\UNC\host\share\amneziawg-tunnel.dll', '\\.\C:\Program Files\Nelomai\amneziawg-tunnel.dll', '\\?\C:relative\amneziawg-tunnel.dll', '\??\C:\Program Files\Nelomai\amneziawg-tunnel.dll', '\\?\C:\Users\fixture\amneziawg-tunnel.dll')) {
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
