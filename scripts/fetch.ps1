# ============================================================================
#  MiscBox - generic downloader
#  Pure ASCII. Downloads to <Out>.part, verifies SHA256 when supplied, then
#  renames. Never leaves a half-written file under the final name.
#
#  Usage:
#    .\fetch.ps1 -Url <url> -Out <path> [-Sha256 <hex>] [-Retries 3]
#    .\fetch.ps1 -Url <url> -Out <path> -Proxy      # retry through gh mirrors
# ============================================================================
param(
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Sha256 = '',
    [int]$Retries = 3,
    [switch]$Proxy
)

$ErrorActionPreference = 'Stop'

$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
if (-not (Test-Path -LiteralPath $curl)) { $curl = 'curl.exe' }

function Get-Hash {
    param([string]$path)
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
}

function Get-ProxyUrl {
    param([string]$u)

    # Public GitHub mirrors. Only rewrite github.com / raw.githubusercontent.com.
    if ($u -match '^https://(github\.com|raw\.githubusercontent\.com|codeload\.github\.com)/') {
        return @(
            ('https://ghfast.top/' + $u),
            ('https://gh-proxy.com/' + $u)
        )
    }

    # SourceForge: the /download landing page is a slow HTML redirect. The
    # direct mirror host skips it entirely and is far faster.
    if ($u -match '^https://sourceforge\.net/projects/(?<proj>[^/]+)/files/(?<rest>.+)/download$') {
        $proj = $Matches['proj']
        $rest = $Matches['rest']
        return @(
            ('https://master.dl.sourceforge.net/project/{0}/{1}?viasf=1' -f $proj, $rest),
            ('https://downloads.sourceforge.net/project/{0}/{1}' -f $proj, $rest)
        )
    }

    return $null
}

$OutDir = Split-Path -Parent $Out
if ($OutDir -and -not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

# Already present and matching? Skip.
if ((Test-Path -LiteralPath $Out) -and $Sha256) {
    $existing = Get-Hash $Out
    if ($existing -eq $Sha256.ToLower()) {
        Write-Host ("  already present, sha256 OK: {0}" -f (Split-Path -Leaf $Out)) -ForegroundColor DarkGray
        exit 0
    }
}

$part = $Out + '.part'
$candidates = New-Object System.Collections.ArrayList
if ($Proxy) {
    # Mirrors first. A direct GitHub connection often stalls for many minutes
    # without ever failing, so trying it first makes the whole download look hung.
    foreach ($p in (Get-ProxyUrl $Url)) { [void]$candidates.Add($p) }
    [void]$candidates.Add($Url)
} else {
    [void]$candidates.Add($Url)
}

# Per-attempt cap. Long enough for a slow mirror to make progress, short enough
# that a stalled connection falls through to the next candidate quickly.
$attemptTimeout = 120

function Get-RemoteSize {
    param([string]$u)
    # HEAD first; fall back to a 1-byte ranged GET (some mirrors reject HEAD).
    $len = & $curl -s --ssl-no-revoke --head --location --max-time 30 $u 2>$null |
        Select-String -Pattern '^content-length:\s*(\d+)' -CaseSensitive:$false |
        ForEach-Object { [int64]$_.Matches[0].Groups[1].Value } |
        Select-Object -Last 1
    if ($len -and $len -gt 0) { return $len }
    $cr = & $curl -s --ssl-no-revoke --location --max-time 30 -r 0-0 -D - -o NUL $u 2>$null |
        Select-String -Pattern '^content-range:\s*bytes\s+\d+-\d+/(\d+)' -CaseSensitive:$false |
        ForEach-Object { [int64]$_.Matches[0].Groups[1].Value } |
        Select-Object -Last 1
    if ($cr -and $cr -gt 0) { return $cr }
    return 0
}

$ok = $false
foreach ($u in $candidates) {
    $total = Get-RemoteSize $u
    if ($total -gt 0) {
        Write-Host ("  size: {0} MB" -f [math]::Round($total / 1MB, 1)) -ForegroundColor DarkGray
        # Budget the attempt at a pessimistic 30 KB/s so a slow-but-working mirror
        # is allowed to finish. A flat cap would abort big files mid-transfer and
        # the retry would restart from zero, which looks like a permanent hang.
        $attemptTimeout = [int][math]::Min(3600, [math]::Max(180, ($total / 30KB)))
    } else {
        $attemptTimeout = 600
    }

    for ($i = 1; $i -le $Retries; $i++) {
        # Resume from whatever is already on disk instead of restarting.
        $resume = 0
        if (Test-Path -LiteralPath $part) {
            $resume = (Get-Item -LiteralPath $part).Length
        }
        if ($total -gt 0 -and $resume -ge $total) { break }

        if ($resume -gt 0) {
            Write-Host ("  resume at {0} MB of {1} MB" -f `
                [math]::Round($resume / 1MB, 1), [math]::Round($total / 1MB, 1)) -ForegroundColor DarkGray
            $extra = @('--continue-at', '-')
        } else {
            Write-Host ("  GET {0}" -f $u) -ForegroundColor DarkGray
            $extra = @()
        }

        $args = @(
            '--location', '--fail', '--silent', '--show-error',
            '--ssl-no-revoke', '--retry', '2', '--retry-delay', '3',
            '--connect-timeout', '20', '--max-time', $attemptTimeout,
            '--speed-limit', '1024', '--speed-time', '60',
            '--output', $part
        ) + $extra + @($u)
        & $curl @args
        $curlExit = $LASTEXITCODE

        $have = 0
        if (Test-Path -LiteralPath $part) { $have = (Get-Item -LiteralPath $part).Length }

        if ($total -gt 0 -and $have -ge $total) { $ok = $true; break }
        if ($curlExit -eq 0 -and $total -eq 0 -and $have -gt 0) { $ok = $true; break }

        if ($curlExit -eq 28) {
            Write-Host ("    attempt {0} timed out at {1} MB" -f $i, [math]::Round($have / 1MB, 1)) -ForegroundColor Yellow
        } elseif ($curlExit -eq 33) {
            # Server ignored the range request; restart this candidate cleanly.
            Write-Host '    server refused resume - restarting this source' -ForegroundColor Yellow
            Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host ("    attempt {0} failed (exit {1})" -f $i, $curlExit) -ForegroundColor Yellow
        }
        Start-Sleep -Seconds 2
    }
    if ($ok) { break }
    if (Test-Path -LiteralPath $part) { Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue }
    Write-Host '    trying next mirror...' -ForegroundColor DarkYellow
}

if (-not $ok) {
    Write-Host ("  FAILED: {0}" -f $Url) -ForegroundColor Red
    if (Test-Path -LiteralPath $part) { Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue }
    exit 1
}

$sizeMB = [math]::Round((Get-Item -LiteralPath $part).Length / 1MB, 1)
Write-Host ("  downloaded {0} MB" -f $sizeMB) -ForegroundColor DarkGray

if ($Sha256) {
    $actual = Get-Hash $part
    if ($actual -ne $Sha256.ToLower()) {
        Write-Host '  SHA256 MISMATCH - file discarded' -ForegroundColor Red
        Write-Host ("    expected {0}" -f $Sha256) -ForegroundColor Red
        Write-Host ("    actual   {0}" -f $actual) -ForegroundColor Red
        Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        exit 2
    }
    Write-Host '  sha256 OK' -ForegroundColor Green
} else {
    Write-Host '  sha256 not supplied - skipping integrity check' -ForegroundColor DarkYellow
}

Move-Item -LiteralPath $part -Destination $Out -Force
Write-Host ("  saved: {0}" -f $Out) -ForegroundColor Green
exit 0
