# Shared by the NSIS pre-extraction hook and the verified service copy/repair.
# Only exact AWG DLL paths are admitted. No directory/process exclusions.
$ErrorActionPreference = 'Stop'
$registry = 'HKLM:\SOFTWARE\Nelomai\Client'
$legacyName = 'ManagedDefenderExclusionPath'
$prefix = $legacyName + 'V1-'

function Normalize-LocalPath([string]$value) {
    if ($value -match '^\\\\\?\\[A-Za-z]:\\') { $value = $value.Substring(4) }
    if ($value -notmatch '^[A-Za-z]:[\\/]') { throw 'Local absolute path required' }
    return [IO.Path]::GetFullPath($value).TrimEnd('\')
}
$installDir = Normalize-LocalPath $env:NELOMAI_DEFENDER_INSTALL_DIR
$privilegedDir = Normalize-LocalPath $env:NELOMAI_DEFENDER_PRIVILEGED_DIR
$version = '[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?'
$generation = '(?:\.stage-)?[0-9a-f]{64}-[0-9a-f]{1,31}'
$sourcePattern = '^' + [regex]::Escape($installDir) + '\\runtime\\engines\\(?:latest|stable)\\' + $version + '\\amneziawg-tunnel\.dll$'
$enginePattern = '^' + [regex]::Escape($privilegedDir) + '\\releases\\' + $generation + '\\engines\\(?:latest|stable)\\' + $version + '\\amneziawg-tunnel\.dll$'
function Test-ManagedPath([string]$path) {
    return ($path -ieq ($installDir + '\amneziawg-tunnel.dll')) -or ($path -imatch $sourcePattern) -or ($path -imatch $enginePattern)
}
function Get-OwnershipName([string]$path) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return $prefix + ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($path.ToLowerInvariant())))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function Read-OwnedPaths {
    if (-not (Test-Path -LiteralPath $registry)) { return @() }
    $values = Get-ItemProperty -LiteralPath $registry
    return @($values.PSObject.Properties | Where-Object {
        ($_.Value -is [string]) -and (Test-ManagedPath $_.Value) -and
        (($_.Name -eq $legacyName) -or ($_.Name -eq (Get-OwnershipName $_.Value)))
    })
}
function Remove-OwnedPath($property) {
    $path = $property.Value
    $existing = @((Get-MpPreference).ExclusionPath)
    if ($existing -icontains $path) { Remove-MpPreference -ExclusionPath $path }
    Remove-ItemProperty -LiteralPath $registry -Name $property.Name
}

switch ($env:NELOMAI_DEFENDER_ACTION) {
    { $_ -eq 'add' -or $_ -eq 'repair' } {
        $path = Normalize-LocalPath $env:NELOMAI_DEFENDER_EXCLUSION_PATH
        if (-not (Test-ManagedPath $path)) { throw 'Unexpected DLL exclusion path' }
        $existing = @((Get-MpPreference).ExclusionPath)
        # Do not claim a user's pre-existing exception. Existing owned entries
        # stay recorded; a separate per-path property never overwrites them.
        if ($existing -icontains $path) {
            if ($env:NELOMAI_DEFENDER_ACTION -eq 'repair') {
                $owned = @(Read-OwnedPaths | Where-Object { $_.Value -ieq $path })
                if ($owned.Count -gt 0) {
                    # Configured membership can lag Defender's effective state.
                    # Refresh only our exact exception; retain its durable owner
                    # record and attempt restoration even when removal fails.
                    try { Remove-MpPreference -ExclusionPath $path }
                    finally { Add-MpPreference -ExclusionPath $path }
                }
            }
            return
        }
        if (-not (Test-Path -LiteralPath $registry)) {
            # SOFTWARE exists on Windows; create the fixed manufacturer parent
            # and Client separately without replacing either existing key.
            $parent = Split-Path -Parent $registry
            if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent | Out-Null }
            New-Item -Path $registry | Out-Null
        }
        # Persist intent before effect: an interrupted Add remains cleanable.
        New-ItemProperty -LiteralPath $registry -Name (Get-OwnershipName $path) -PropertyType String -Value $path -Force | Out-Null
        Add-MpPreference -ExclusionPath $path
    }
    'remove' {
        $path = Normalize-LocalPath $env:NELOMAI_DEFENDER_EXCLUSION_PATH
        if (-not (Test-ManagedPath $path)) { throw 'Unexpected DLL exclusion path' }
        foreach ($property in (Read-OwnedPaths)) {
            if ($property.Value -ieq $path) { Remove-OwnedPath $property }
        }
    }
    'cleanup' {
        foreach ($property in (Read-OwnedPaths)) { Remove-OwnedPath $property }
    }
    default { throw 'Unsupported managed exclusion operation' }
}
