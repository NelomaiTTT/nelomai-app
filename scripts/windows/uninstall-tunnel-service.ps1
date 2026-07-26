param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceExecutable
)

$ErrorActionPreference = "Stop"

$servicePath = (Resolve-Path -LiteralPath $ServiceExecutable).Path
$process = Start-Process `
    -FilePath $servicePath `
    -ArgumentList @("uninstall") `
    -Verb RunAs `
    -Wait `
    -PassThru

if ($process.ExitCode -ne 0) {
    throw "Nelomai tunnel service removal failed with exit code $($process.ExitCode)."
}
