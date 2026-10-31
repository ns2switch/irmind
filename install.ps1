# Install a verified IRMind release for the current Windows user.
param(
    [string]$Version = 'latest',
    [string]$InstallDir = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'IRMind', 'bin')
)
$ErrorActionPreference = 'Stop'
$repo = 'ns2switch/irmind'
$issuer = 'https://token.actions.githubusercontent.com'

function Fail([string]$Message) { throw "IRMind installer: $Message" }

function Download-Https([string]$Url, [string]$Destination, [long]$MaximumBytes) {
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(90)
    try {
        $current = [System.Uri]::new($Url)
        for ($redirects = 0; $redirects -le 5; $redirects++) {
            if ($current.Scheme -ne 'https') { Fail 'a download tried to leave HTTPS' }
            $response = $client.GetAsync($current, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            try {
                if ([int]$response.StatusCode -ge 300 -and [int]$response.StatusCode -lt 400) {
                    if ($null -eq $response.Headers.Location) { Fail 'a redirect has no destination' }
                    $current = [System.Uri]::new($current, $response.Headers.Location)
                    continue
                }
                if (-not $response.IsSuccessStatusCode) { Fail "download failed with HTTP $([int]$response.StatusCode)" }
                if ($response.Content.Headers.ContentLength -gt $MaximumBytes) { Fail 'download is larger than its size limit' }
                $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $outputStream = [System.IO.File]::Create($Destination)
                try {
                    $buffer = New-Object byte[] 65536
                    [long]$total = 0
                    while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $total += $count
                        if ($total -gt $MaximumBytes) { Fail 'download is larger than its size limit' }
                        $outputStream.Write($buffer, 0, $count)
                    }
                } finally {
                    $outputStream.Dispose()
                    $inputStream.Dispose()
                }
                return
            } finally { $response.Dispose() }
        }
        Fail 'too many HTTPS redirects'
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

if ($Version -ne 'latest' -and $Version -cnotmatch '^v[0-9][A-Za-z0-9._-]*$') { Fail 'invalid release tag' }
if (-not [System.IO.Path]::IsPathRooted($InstallDir)) { Fail 'the installation directory must be absolute' }
if (-not $env:USERPROFILE) { Fail 'the current user directory is unavailable' }
$userRoot = [System.IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\') + '\'
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
if (-not $InstallDir.StartsWith($userRoot, [System.StringComparison]::OrdinalIgnoreCase)) { Fail 'install inside the current user directory' }
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { Fail 'no Windows release binary for this architecture; build from source' }

$temporary = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), 'irmind-install-' + [System.Guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($temporary) | Out-Null
try {
    if ($Version -eq 'latest') {
        $releasesFile = Join-Path $temporary 'releases.json'
        Download-Https "https://api.github.com/repos/$repo/releases?per_page=10" $releasesFile 1048576
        $releases = ConvertFrom-Json ([System.IO.File]::ReadAllText($releasesFile))
        $Version = @($releases | Where-Object { -not $_.draft } | Select-Object -First 1)[0].tag_name
        if ($Version -cnotmatch '^v[0-9][A-Za-z0-9._-]*$') { Fail 'GitHub returned no valid release tag' }
    }
    $asset = 'irmind-windows-x86_64.exe'
    $base = "https://github.com/$repo/releases/download/$Version"
    $binary = Join-Path $temporary $asset
    $checksums = Join-Path $temporary 'SHA256SUMS'
    Download-Https "$base/SHA256SUMS" $checksums 1048576
    Download-Https "$base/$asset" $binary 262144000

    $line = @([System.IO.File]::ReadAllLines($checksums) | Where-Object { $_ -cmatch ('^[0-9a-f]{64}  ' + [regex]::Escape($asset) + '$') })
    if ($line.Count -ne 1) { Fail 'missing or duplicate SHA-256 entry for the binary' }
    $expected = $line[0].Substring(0, 64)
    $actual = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $expected) { Fail 'SHA-256 mismatch; nothing was installed' }

    if (Get-Command cosign -ErrorAction SilentlyContinue) {
        $identity = "https://github.com/$repo/.github/workflows/ci.yml@refs/tags/$Version"
        foreach ($file in @($asset, 'SHA256SUMS')) {
            $bundle = Join-Path $temporary "$file.sigstore.json"
            Download-Https "$base/$file.sigstore.json" $bundle 1048576
            & cosign verify-blob (Join-Path $temporary $file) --bundle $bundle --certificate-identity $identity --certificate-oidc-issuer $issuer | Out-Null
            if ($LASTEXITCODE -ne 0) { Fail "Sigstore verification failed for $file; nothing was installed" }
        }
    } else {
        Write-Warning 'cosign is unavailable; verify the published Sigstore bundles manually for publisher identity.'
    }
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        & gh attestation verify $binary -R $repo | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail 'GitHub provenance verification failed; nothing was installed' }
    } else {
        Write-Warning "gh is unavailable; run gh attestation verify $asset -R $repo after downloading it."
    }

    [System.IO.Directory]::CreateDirectory($InstallDir) | Out-Null
    $stage = Join-Path $InstallDir ('.irmind-install-' + [System.Guid]::NewGuid().ToString('N') + '.exe')
    try {
        Copy-Item -LiteralPath $binary -Destination $stage
        Move-Item -LiteralPath $stage -Destination (Join-Path $InstallDir 'irmind.exe') -Force
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Force }
    }
    Write-Host "Installed IRMind $Version at $InstallDir\irmind.exe"
    if (-not (($env:PATH -split ';') -contains $InstallDir)) {
        Write-Host "Add $InstallDir to PATH when ready. This script did not change PATH."
    }
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
