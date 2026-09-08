$ErrorActionPreference = "Stop"
# The same immutable source archive and digest as the pinned upstream build.bat.
$url = "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-06a99cce2c9998f53eb30d2f258a9e5ff286445b.zip"
$expected = "b7a73e027cee3127f3cccba8ad3a08ea61ccd42d3ea5c28c548a8e0ec9e10cf6"
$gitRoot = Split-Path (Split-Path (Get-Command git.exe).Source -Parent) -Parent
$clients = @{
    system = Join-Path ([Environment]::SystemDirectory) "curl.exe"
    git = Join-Path $gitRoot "mingw64/bin/curl.exe"
}
$work = Join-Path ([IO.Path]::GetTempPath()) ("nelomai-download-check-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory $work | Out-Null
$passed = 0
foreach ($name in @("system", "git")) {
    $client = $clients[$name]
    if (-not (Test-Path -LiteralPath $client -PathType Leaf)) {
        throw "Missing diagnostic curl: $name"
    }
    Write-Output "CLIENT=$name PATH=$client"
    & $client --version
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $archive = Join-Path $work "$name-$attempt.zip"
        & $client --fail --location --silent --show-error --connect-timeout 10 --max-time 30 --output $archive $url
        $code = $LASTEXITCODE
        $hash = if (Test-Path -LiteralPath $archive) { (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() } else { "absent" }
        Write-Output "RESULT client=$name attempt=$attempt exit=$code sha256=$hash matches=$($hash -eq $expected)"
        if ($code -eq 0 -and $hash -eq $expected) { $passed++ }
        if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive }
    }
}
Remove-Item -LiteralPath $work
if ($passed -eq 0) { throw "Neither curl downloaded the pinned archive successfully" }
