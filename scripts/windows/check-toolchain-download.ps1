$ErrorActionPreference = "Stop"
# The same immutable source archive and digest as the pinned upstream build.bat.
$url = "https://codeload.github.com/WireGuard/wireguard-tools/zip/06a99cce2c9998f53eb30d2f258a9e5ff286445b"
$expected = "209db11b588eb4dc55a05ee70ceea44690ddad44e945d8299e95465a5dec4d7d"
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
