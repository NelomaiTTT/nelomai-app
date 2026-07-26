param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceExecutable,

    [Parameter(Mandatory = $true)]
    [string]$ClientExecutable
)

$ErrorActionPreference = "Stop"

$servicePath = (Resolve-Path -LiteralPath $ServiceExecutable).Path
$clientPath = (Resolve-Path -LiteralPath $ClientExecutable).Path
$ownerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

$arguments = @(
    "install",
    "--owner-sid",
    $ownerSid,
    "--client-path",
    "`"$clientPath`""
)

$process = Start-Process `
    -FilePath $servicePath `
    -ArgumentList $arguments `
    -Verb RunAs `
    -Wait `
    -PassThru

if ($process.ExitCode -ne 0) {
    throw "Nelomai tunnel service installation failed with exit code $($process.ExitCode)."
}
