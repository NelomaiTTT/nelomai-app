param(
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$WireGuardWindowsCommit = "4e6726c23ae9c5cb58e0c9910f3b7515621d133d"
$WireGuardNtVersion = "1.1"
$WireGuardNtArchiveSha256 = "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace"
$AmneziaWgWindowsCommit = "575626d8f8aa5b64114cf378a08e54bf852d909b"

$root = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $root "src-tauri/windows/runtime"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$work = Join-Path ([System.IO.Path]::GetTempPath()) "nelomai-wireguard-runtime"
$source = Join-Path $work "wireguard-windows"
$amneziaSource = Join-Path $work "amneziawg-windows"
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

git init $amneziaSource
git -C $amneziaSource remote add origin https://github.com/amnezia-vpn/amneziawg-windows.git
git -C $amneziaSource fetch --depth 1 origin $AmneziaWgWindowsCommit
git -C $amneziaSource checkout --detach FETCH_HEAD
$amneziaBuild = Join-Path $amneziaSource "build.cmd"
$amneziaBuildText = Get-Content -LiteralPath $amneziaBuild -Raw
$amneziaBuildOriginal = $amneziaBuildText
$amneziaBuildText = $amneziaBuildText.Replace(
    "go1.24.4.windows-amd64.zip b751a1136cb9d8a2e7ebb22c538c4f02c09b98138c7c8bfb78a54a4566c013b1",
    "go1.25.0.windows-amd64.zip 89efb4f9b30812eee083cc1770fdd2913c14d301064f6454851428f9707d190b"
)
if ($amneziaBuildText -eq $amneziaBuildOriginal) {
    throw "Pinned AmneziaWG build script no longer contains the expected Go toolchain"
}
Set-Content -LiteralPath $amneziaBuild -Value $amneziaBuildText -Encoding ASCII
& cmd.exe /c $amneziaBuild
if ($LASTEXITCODE -ne 0) {
    throw "AmneziaWG tunnel.dll build failed with exit code $LASTEXITCODE"
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
$amneziaTunnelDll = Join-Path $amneziaSource "x64/tunnel.dll"
$amneziaWindowsReadme = Join-Path $amneziaSource "README.md"
$wintunDll = Join-Path $amneziaSource ".deps/wintun/bin/amd64/wintun.dll"
$wintunLicense = Join-Path $amneziaSource ".deps/wintun/LICENSE.txt"
$amneziaGoLicense = Join-Path $root "vendor/amneziawg-go/LICENSE"
foreach ($required in @(
    $tunnelDll,
    $wireGuardDll,
    $wireGuardWindowsLicense,
    $wireGuardNtLicense,
    $amneziaTunnelDll,
    $amneziaWindowsReadme,
    $wintunDll,
    $wintunLicense,
    $amneziaGoLicense
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required Windows runtime file is missing: $required"
    }
}

Copy-Item $tunnelDll (Join-Path $OutputDirectory "tunnel.dll") -Force
Copy-Item $wireGuardDll (Join-Path $OutputDirectory "wireguard.dll") -Force
Copy-Item $wireGuardWindowsLicense (Join-Path $OutputDirectory "WIREGUARD-WINDOWS-LICENSE.txt") -Force
Copy-Item $wireGuardNtLicense (Join-Path $OutputDirectory "WIREGUARD-NT-LICENSE.txt") -Force
Copy-Item $amneziaTunnelDll (Join-Path $OutputDirectory "amneziawg-tunnel.dll") -Force
Copy-Item $amneziaWindowsReadme (Join-Path $OutputDirectory "AMNEZIAWG-WINDOWS-README.txt") -Force
Copy-Item $wintunDll (Join-Path $OutputDirectory "wintun.dll") -Force
Copy-Item $wintunLicense (Join-Path $OutputDirectory "WINTUN-LICENSE.txt") -Force
Copy-Item $amneziaGoLicense (Join-Path $OutputDirectory "AMNEZIAWG-GO-LICENSE.txt") -Force

$metadata = [ordered]@{
    wireguard_windows_commit = $WireGuardWindowsCommit
    wireguard_nt_version = $WireGuardNtVersion
    wireguard_nt_archive_sha256 = $WireGuardNtArchiveSha256
    tunnel_dll_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $OutputDirectory "tunnel.dll")).Hash.ToLowerInvariant()
    wireguard_dll_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $OutputDirectory "wireguard.dll")).Hash.ToLowerInvariant()
    amneziawg_windows_commit = $AmneziaWgWindowsCommit
    amneziawg_tunnel_dll_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $OutputDirectory "amneziawg-tunnel.dll")).Hash.ToLowerInvariant()
    wintun_version = "0.14.1"
    wintun_dll_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $OutputDirectory "wintun.dll")).Hash.ToLowerInvariant()
}
$metadata | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $OutputDirectory "windows-runtime.json")
