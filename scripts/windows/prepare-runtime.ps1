param(
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$WireGuardWindowsCommit = "4e6726c23ae9c5cb58e0c9910f3b7515621d133d"
$WireGuardNtVersion = "1.1"
$WireGuardNtArchiveSha256 = "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace"

$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $root "src-tauri/windows/runtime"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$work = Join-Path ([System.IO.Path]::GetTempPath()) "nelomai-wireguard-runtime"
$source = Join-Path $work "wireguard-windows"
$archive = Join-Path $work "wireguard-nt.zip"
$expanded = Join-Path $work "wireguard-nt"

if (Test-Path $work) {
    Remove-Item -Recurse -Force $work
}
New-Item -ItemType Directory -Force $work | Out-Null
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null

git init $source
git -C $source remote add origin https://github.com/WireGuard/wireguard-windows.git
git -C $source fetch --depth 1 origin $WireGuardWindowsCommit
git -C $source checkout --detach FETCH_HEAD
& cmd.exe /c (Join-Path $source "embeddable-dll-service/build.bat")
if ($LASTEXITCODE -ne 0) {
    throw "WireGuard tunnel.dll build failed with exit code $LASTEXITCODE"
}

$archiveUrl = "https://download.wireguard.com/wireguard-nt/wireguard-nt-$WireGuardNtVersion.zip"
Invoke-WebRequest -UseBasicParsing $archiveUrl -OutFile $archive
$archiveHash = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
if ($archiveHash -ne $WireGuardNtArchiveSha256) {
    throw "WireGuardNT archive hash mismatch: $archiveHash"
}
Expand-Archive -Path $archive -DestinationPath $expanded

$tunnelDll = Join-Path $source "embeddable-dll-service/amd64/tunnel.dll"
$wireGuardDll = Join-Path $expanded "wireguard-nt/bin/amd64/wireguard.dll"
$wireGuardWindowsLicense = Join-Path $source "COPYING"
$wireGuardNtLicense = Join-Path $expanded "wireguard-nt/LICENSE.txt"
foreach ($required in @($tunnelDll, $wireGuardDll, $wireGuardWindowsLicense, $wireGuardNtLicense)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required Windows runtime file is missing: $required"
    }
}

Copy-Item $tunnelDll (Join-Path $OutputDirectory "tunnel.dll") -Force
Copy-Item $wireGuardDll (Join-Path $OutputDirectory "wireguard.dll") -Force
Copy-Item $wireGuardWindowsLicense (Join-Path $OutputDirectory "WIREGUARD-WINDOWS-LICENSE.txt") -Force
Copy-Item $wireGuardNtLicense (Join-Path $OutputDirectory "WIREGUARD-NT-LICENSE.txt") -Force

$metadata = [ordered]@{
    wireguard_windows_commit = $WireGuardWindowsCommit
    wireguard_nt_version = $WireGuardNtVersion
    wireguard_nt_archive_sha256 = $WireGuardNtArchiveSha256
    tunnel_dll_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $OutputDirectory "tunnel.dll")).Hash.ToLowerInvariant()
    wireguard_dll_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $OutputDirectory "wireguard.dll")).Hash.ToLowerInvariant()
}
$metadata | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "windows-runtime.json")
