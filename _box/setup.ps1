# ============================================================================
#  MiscBox - environment check / self-heal script
#  Pure ASCII on purpose: PowerShell 5.1 reads .ps1 as GBK when there is no BOM,
#  and non-ASCII text then breaks the parser. All Chinese text lives in
#  tools.json and the generated report instead.
#
#  Usage:
#    powershell -NoProfile -ExecutionPolicy Bypass -File setup.ps1
#    powershell -NoProfile -ExecutionPolicy Bypass -File setup.ps1 -Json
#    powershell -NoProfile -ExecutionPolicy Bypass -File setup.ps1 -Quiet
# ============================================================================
param(
    [switch]$Json,
    [switch]$Quiet,
    [switch]$Fix
)

$ErrorActionPreference = 'Continue'
$BoxDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root    = Split-Path -Parent $BoxDir
$ReportPath = Join-Path $BoxDir 'env-report.json'

$checks = New-Object System.Collections.ArrayList

function Add-Check {
    param(
        [string]$Id,
        [string]$Name,
        [string]$Category,
        [string]$Status,   # ok | warn | miss | info
        [string]$Detail,
        [string]$Hint = ''
    )
    [void]$checks.Add([pscustomobject]@{
        id = $Id; name = $Name; category = $Category
        status = $Status; detail = $Detail; hint = $Hint
    })
}

function Test-PathSafe {
    param([string]$p)
    if ([string]::IsNullOrWhiteSpace($p)) { return $false }
    try { return Test-Path -LiteralPath $p } catch { return $false }
}

function Get-CmdPath {
    param([string]$name)
    $c = Get-Command $name -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    return $null
}

# ---------------------------------------------------------------------------
#  1. Runtimes
# ---------------------------------------------------------------------------

# Python 3.14 (main runtime)
$py314 = Join-Path $env:LOCALAPPDATA 'Python\pythoncore-3.14-64\python.exe'
if (-not (Test-PathSafe $py314)) {
    $alt = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Python') -Filter 'python.exe' -Recurse -ErrorAction SilentlyContinue |
           Select-Object -First 1
    if ($alt) { $py314 = $alt.FullName }
}
if (Test-PathSafe $py314) {
    $v = (& $py314 -V 2>&1) -join ' '
    Add-Check 'python314' 'Python 3.14 (main runtime)' 'runtime' 'ok' "$v  $py314"
    # Pillow
    $pil = (& $py314 -c "import PIL;print(PIL.__version__)" 2>&1) -join ''
    if ($LASTEXITCODE -eq 0 -and $pil) {
        Add-Check 'pillow' 'Pillow (image processing)' 'runtime' 'ok' "Pillow $pil"
    } else {
        Add-Check 'pillow' 'Pillow (image processing)' 'runtime' 'warn' 'not installed' `
            "pip install pillow -i https://pypi.tuna.tsinghua.edu.cn/simple"
    }
    # tkinter
    $tk = (& $py314 -c "import tkinter;print(tkinter.TkVersion)" 2>&1) -join ''
    if ($LASTEXITCODE -eq 0 -and $tk) {
        Add-Check 'tkinter' 'tkinter (launcher GUI)' 'runtime' 'ok' "Tk $tk"
    } else {
        Add-Check 'tkinter' 'tkinter (launcher GUI)' 'runtime' 'miss' 'not available in this Python build' `
            'Install a python.org build which ships Tk.'
    }
} else {
    Add-Check 'python314' 'Python 3.14 (main runtime)' 'runtime' 'miss' 'not found' `
        'https://www.python.org/downloads/'
}

# Python for virtualenvs (binwalk / volatility / theHarvester)
# Prefer a real 3.12/3.13 if present, but accept whatever secondary Python
# exists: those three tools only need "some Python that can build a venv".
# Report the version that was actually found - labelling a 3.14 as "3.12" just
# because 3.12 was the first candidate would be a lie in the report.
$pyVenv = $null
foreach ($c in @(                 (Join-Path $env:LOCALAPPDATA 'Python\pythoncore-3.12-64\python.exe'),
                 (Join-Path $env:LOCALAPPDATA 'Python\pythoncore-3.13-64\python.exe'),
                 (Join-Path $env:LOCALAPPDATA 'Python\pythoncore-3.14-64\python.exe'))) {
    if (Test-PathSafe $c) { $pyVenv = $c; break }
}
if (-not $pyVenv) {
    $cmd = Get-Command 'python' -ErrorAction SilentlyContinue
    if ($cmd) { $pyVenv = $cmd.Source }
}
if (Test-PathSafe $pyVenv) {
    $v = (& $pyVenv -V 2>&1) -join ' '
    $m = [regex]::Match($v, '(\d+\.\d+)')
    $label = if ($m.Success) { "Python $($m.Groups[1].Value) (venv base)" } else { 'Python (venv base)' }
    Add-Check 'python-venv-base' $label 'runtime' 'ok' "$v  $pyVenv"
} else {
    Add-Check 'python-venv-base' 'Python (venv base)' 'runtime' 'warn' 'no secondary Python found' `
        'Needed as the venv base for binwalk / volatility3 / theHarvester.'
}

# Java
$java = Get-CmdPath 'java'
if ($java) {
    $line = (& java -version 2>&1 | Select-Object -First 1) -join ''
    Add-Check 'java' 'Java runtime (StegSolve)' 'runtime' 'ok' "$line  $java"
} else {
    Add-Check 'java' 'Java runtime (StegSolve)' 'runtime' 'miss' 'java not on PATH' `
        'Install Microsoft OpenJDK 17 or any JRE 8+.'
}

# Node (optional, for JS-based tooling)
$node = Get-CmdPath 'node'
if ($node) {
    $v = (& node -v 2>&1) -join ''
    Add-Check 'node' 'Node.js (optional)' 'runtime' 'ok' "$v  $node"
} else {
    Add-Check 'node' 'Node.js (optional)' 'runtime' 'info' 'not found (optional)'
}

# ---------------------------------------------------------------------------
#  2. Tools by category
# ---------------------------------------------------------------------------

# Resolve a category directory by its numeric prefix (e.g. "04").
# Category folders carry Chinese names, and a .ps1 without a BOM is read as GBK
# by PowerShell 5.1, so we never hard-code those names in this ASCII-only file.
function Get-CatDir {
    param([string]$prefix, [string]$fallback = '')
    try {
        $d = Get-ChildItem -LiteralPath $Root -Directory -ErrorAction Stop |
             Where-Object { $_.Name -like ($prefix + '-*') } |
             Select-Object -First 1
        if ($d) { return $d.FullName }
    } catch { }
    if ($fallback) { return (Join-Path $Root $fallback) }
    return (Join-Path $Root $prefix)
}

function Add-ToolCheck {
    param([string]$Id, [string]$Name, [string]$Category, [string]$Path, [string]$Hint = '', [string]$VersionCmd = '')
    $full = $Path
    if (-not [System.IO.Path]::IsPathRooted($full)) { $full = Join-Path $Root ($full -replace '/', '\') }
    if (Test-PathSafe $full) {
        $detail = $full
        if ($VersionCmd) {
            try {
                $out = (& powershell -NoProfile -Command $VersionCmd 2>&1 | Select-Object -First 1) -join ''
                if ($out) { $detail = "$out  |  $full" }
            } catch { }
        }
        Add-Check $Id $Name $Category 'ok' $detail
    } else {
        Add-Check $Id $Name $Category 'miss' "missing: $full" $Hint
    }
}

# --- archive ---
Add-ToolCheck '7zip' '7-Zip' 'archive' 'C:\Program Files\7-Zip\7z.exe' 'Install 7-Zip, or keep the portable copy under CTF-tools\7zip.'
Add-ToolCheck '7zip-portable' '7-Zip portable 24.09' 'archive' 'CTF-tools\7zip\7z.exe' 'Optional portable copy.'
Add-ToolCheck 'archpr' 'ARCHPR 4.66' 'archive' 'ARCHPR\ARCHPR.loader.exe' 'Commercial tool, not redistributable; supply your own copy.'
Add-ToolCheck 'john' 'John the Ripper jumbo' 'archive' 'john\john-1.9.0-jumbo-1-win64\run\john.exe' 'Download john-1.9.0-jumbo-1-win64.zip from openwall.com'
Add-ToolCheck 'hashcat' 'hashcat 7.1.2' 'archive' 'hashcat\hashcat.exe' 'Download hashcat-7.1.2.7z from hashcat.net'

$hcPanel = Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'hashcat*' -and $_.Name -ne 'hashcat' } | Select-Object -First 1
if ($hcPanel) {
    $hcExe = Join-Path $hcPanel.FullName '??\HashcatPanel.exe'
    if (Test-PathSafe $hcExe) { Add-Check 'hashcat-panel' 'Hashcat Panel' 'archive' 'ok' $hcExe }
    else { Add-Check 'hashcat-panel' 'Hashcat Panel' 'archive' 'info' 'optional GUI wrapper not installed' }
}
Add-ToolCheck 'perl' 'Strawberry Perl portable' 'archive' (Join-Path (Get-CatDir '04') 'perl\perl\bin\perl.exe') 'Run: setup.ps1 -Fix  (or download strawberry-perl portable)'

# --- code ---
Add-ToolCheck 'cyberchef' 'CyberChef 11.5.0' 'code' (Join-Path (Get-CatDir '02') 'CyberChef\CyberChef_v11.5.0.html') 'Run: setup.ps1 -Fix  (or download the CyberChef release zip)'

# --- stego ---
Add-ToolCheck 'stegsolve' 'StegSolve 1.4' 'stego' 'StegSolve\StegSolve-1.4.jar' 'Needs Java. Place StegSolve-1.4.jar under StegSolve\.'
Add-ToolCheck 'pngcheck' 'pngcheck suite' 'stego' 'pngcheck\pngcheck.exe' 'Download pngcheck-3.0.3.zip and build, or copy the binaries.'
Add-ToolCheck 'exiftool' 'ExifTool 13.59' 'stego' 'CTF-tools\exiftool\exiftool.exe' 'Download exiftool from exiftool.org'
$scriptDir = Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '_*' -and (Test-Path (Join-Path $_.FullName 'imgsize.py')) } | Select-Object -First 1
if ($scriptDir) { Add-Check 'imgsize' 'imgsize.py' 'stego' 'ok' (Join-Path $scriptDir.FullName 'imgsize.py') }
else { Add-Check 'imgsize' 'imgsize.py' 'stego' 'miss' 'imgsize.py not found' 'Ships with the toolbox under the script folder.' }

# --- forensics ---
Add-ToolCheck 'binwalk' 'binwalk 2.3.4' 'forensics' 'binwalk\binwalk.bat' 'See docs: needs a Windows patch before it installs.'
Add-ToolCheck 'foremost' 'foremost 1.5.7' 'forensics' 'foremost\foremost.exe' 'Self-compiled with MinGW; see docs.'
Add-ToolCheck 'volatility3' 'Volatility 3' 'forensics' (Join-Path (Get-CatDir '06') 'volatility3\venv\Scripts\vol.exe') 'Run: setup.ps1 -Fix  (pip install volatility3 in a venv)'

# --- traffic ---
Add-ToolCheck 'tshark' 'Wireshark / tshark' 'traffic' 'C:\Program Files\Wireshark\tshark.exe' 'Install Wireshark (needs admin).'
Add-ToolCheck 'nmap' 'nmap 7.992' 'traffic' (Join-Path (Get-CatDir '05') 'nmap\nmap.exe') 'Run: setup.ps1 -Fix  (extracts the portable copy)'

# --- osint ---
Add-ToolCheck 'theharvester' 'theHarvester 4.11.1' 'osint' (Join-Path (Get-CatDir '07') 'theharvester\venv\Scripts\theHarvester.exe') 'Run: setup.ps1 -Fix  (pip install from source)'

# Npcap (only needed for live capture)
$npcapDir = Join-Path $env:SystemRoot 'System32\Npcap'
if (Test-PathSafe $npcapDir) {
    Add-Check 'npcap' 'Npcap (live capture driver)' 'traffic' 'ok' $npcapDir
} else {
    Add-Check 'npcap' 'Npcap (live capture driver)' 'traffic' 'warn' `
        'not installed - pcap FILE analysis still works, live capture does not' `
        'Free Npcap has no silent install; run npcap-*.exe and click through the wizard.'
}

# ---------------------------------------------------------------------------
#  3. Writable config dirs used by third-party tools
# ---------------------------------------------------------------------------

$dirs = @(
    @{ p = (Join-Path $env:USERPROFILE '.theHarvester');  n = 'theHarvester config dir' },
    @{ p = (Join-Path $env:USERPROFILE '.local\share\theHarvester'); n = 'theHarvester data dir' },
    @{ p = (Join-Path $env:APPDATA 'volatility3');        n = 'Volatility symbol cache' }
)
foreach ($d in $dirs) {
    if (Test-PathSafe $d.p) {
        Add-Check ('dir_' + ($d.n -replace '[^A-Za-z0-9]', '_')) $d.n 'runtime' 'ok' $d.p
    } else {
        $created = $false
        try { New-Item -ItemType Directory -Path $d.p -Force -ErrorAction Stop | Out-Null; $created = $true } catch { }
        if ($created) {
            Add-Check ('dir_' + ($d.n -replace '[^A-Za-z0-9]', '_')) $d.n 'runtime' 'ok' "created: $($d.p)"
        } else {
            Add-Check ('dir_' + ($d.n -replace '[^A-Za-z0-9]', '_')) $d.n 'runtime' 'warn' "cannot create: $($d.p)" `
                'Create it manually or the tool will fail with a permission error.'
        }
    }
}

# ---------------------------------------------------------------------------
#  4. Optional: -Fix (best effort, never silent)
# ---------------------------------------------------------------------------

if ($Fix) {
    Write-Host ''
    Write-Host '=== -Fix requested ===' -ForegroundColor Cyan
    $missing = $checks | Where-Object { $_.status -eq 'miss' }
    foreach ($m in $missing) {
        Write-Host ("  [{0}] {1}" -f $m.id, $m.name) -ForegroundColor Yellow
        if ($m.hint) { Write-Host ("      hint: {0}" -f $m.hint) -ForegroundColor DarkGray }
    }
    Write-Host ''
    Write-Host 'Automatic install is not enabled in this build.' -ForegroundColor Yellow
    Write-Host 'Each tool needs a different source (pip / GitHub / vendor installer).' -ForegroundColor Yellow
    Write-Host 'See the README.md inside each category folder for the per-tool commands.' -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
#  5. Output
# ---------------------------------------------------------------------------

$summary = [pscustomobject]@{
    generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    root      = $Root
    ok        = @($checks | Where-Object { $_.status -eq 'ok' }).Count
    warn      = @($checks | Where-Object { $_.status -eq 'warn' }).Count
    miss      = @($checks | Where-Object { $_.status -eq 'miss' }).Count
    info      = @($checks | Where-Object { $_.status -eq 'info' }).Count
}

$payload = [pscustomobject]@{ summary = $summary; checks = $checks }
try {
    $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    Write-Host ("Report written: {0}" -f $ReportPath) -ForegroundColor DarkGray
} catch {
    Write-Host ("Could not write report: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

if ($Json) {
    $payload | ConvertTo-Json -Depth 5
    exit 0
}

if (-not $Quiet) {
    Write-Host ''
    Write-Host '================ MiscBox environment ================' -ForegroundColor Cyan
    Write-Host ("  root: {0}" -f $Root)
    Write-Host ("  ok={0}  warn={1}  miss={2}" -f $summary.ok, $summary.warn, $summary.miss) -ForegroundColor Gray
    Write-Host '=====================================================' -ForegroundColor Cyan
}

$lastCat = ''
foreach ($c in $checks) {
    if ($c.category -ne $lastCat) {
        Write-Host ''
        Write-Host ("--- {0} ---" -f $c.category.ToUpper()) -ForegroundColor DarkCyan
        $lastCat = $c.category
    }
    switch ($c.status) {
        'ok'   { $color = 'Green';  $mark = 'OK  ' }
        'warn' { $color = 'Yellow'; $mark = 'WARN' }
        'miss' { $color = 'Red';    $mark = 'MISS' }
        default { $color = 'Gray';  $mark = 'INFO' }
    }
    if ($Quiet -and $c.status -eq 'ok') { continue }
    Write-Host ("  [{0}] {1}" -f $mark, $c.name) -ForegroundColor $color
    Write-Host ("         {0}" -f $c.detail) -ForegroundColor DarkGray
    if ($c.hint -and $c.status -ne 'ok') {
        Write-Host ("         -> {0}" -f $c.hint) -ForegroundColor DarkYellow
    }
}

Write-Host ''
if ($summary.miss -gt 0) {
    Write-Host ("{0} item(s) missing. See the README.md in each category folder." -f $summary.miss) -ForegroundColor Yellow
} else {
    Write-Host 'All required components are present.' -ForegroundColor Green
}
exit 0









