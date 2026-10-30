# ============================================================================
#  MiscBox - bootstrap
#  Reads scripts\tools-manifest.json, shows what is missing, asks per tool,
#  downloads + extracts. Pure ASCII on purpose (PS 5.1 reads .ps1 as GBK
#  without a BOM, so non-ASCII source text breaks the parser).
#
#  Usage:
#    .\bootstrap.ps1                 # show status only, download nothing
#    .\bootstrap.ps1 -Interactive    # ask per tool, then download
#    .\bootstrap.ps1 -Only cyberchef,nmap
#    .\bootstrap.ps1 -Yes            # download all auto=true without asking
#    .\bootstrap.ps1 -Help           # print this usage and exit
# ============================================================================
param(
    [switch]$Interactive,
    [switch]$Yes,
    [string]$Only = '',
    [switch]$Json,
    [switch]$Help
)

if ($Help) {
    Write-Host ''
    Write-Host '  MiscBox bootstrap - download the tools this box needs' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Usage:' -ForegroundColor Gray
    Write-Host '    bootstrap.ps1                 show status only, download nothing'
    Write-Host '    bootstrap.ps1 -Interactive    ask before each tool, then download'
    Write-Host '    bootstrap.ps1 -Only a,b,c     only these tool ids'
    Write-Host '    bootstrap.ps1 -Yes            download every auto tool without asking'
    Write-Host '    bootstrap.ps1 -Json           machine-readable status'
    Write-Host '    bootstrap.ps1 -Help           this text'
    Write-Host ''
    Write-Host '  Tool ids come from scripts\tools-manifest.json:' -ForegroundColor Gray
    $mf = Join-Path $PSScriptRoot 'tools-manifest.json'
    if (Test-Path -LiteralPath $mf) {
        $mj = Get-Content -LiteralPath $mf -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($t in @($mj.tools)) {
            $flag = if ($t.auto) { 'auto' } else { 'manual' }
            Write-Host ("    {0,-14} {1,-16} [{2}]" -f $t.id, $t.name, $flag)
        }
    }
    Write-Host ''
    Write-Host '  Nothing is installed without an explicit yes.' -ForegroundColor Gray
    Write-Host ''
    exit 0
}

$ErrorActionPreference = 'Continue'

# Chinese names are built from code points: this file must stay pure ASCII
# because PowerShell 5.1 reads a BOM-less .ps1 as GBK.
$script:CatForensics = '06-' + [char]0x53D6 + [char]0x8BC1
$script:LaunchPrefix = [string][char]0x542F + [char]0x52A8
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
$ManifestPath = Join-Path $ScriptDir 'tools-manifest.json'
$Fetch = Join-Path $ScriptDir 'fetch.ps1'

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    Write-Host "Manifest not found: $ManifestPath" -ForegroundColor Red
    exit 1
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$defaults = $manifest.defaults

# NOTE: never name this $only. PowerShell variable names are case-insensitive,
# so $only IS the [string]$Only parameter declared above; assigning @() to it
# coerces the array back into an empty string, and ''.Count is 1, which then
# filters out every tool and the script reports "installed 0 / 0".
$onlyIds = @()
if (-not [string]::IsNullOrWhiteSpace($Only)) {
    $onlyIds = @($Only.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Resolve-Target {
    param($tool)
    $t = $tool.target
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }
    if ([System.IO.Path]::IsPathRooted($t)) { return $t }
    return (Join-Path $RepoRoot ($t -replace '/', '\'))
}

function Test-Installed {
    param($tool)
    $entry = $tool.entry
    if ([string]::IsNullOrWhiteSpace($entry)) { return $false }
    if ($entry -match '^[A-Za-z]:/') { return (Test-Path -LiteralPath ($entry -replace '/', '\')) }
    $target = Resolve-Target $tool
    if (-not $target) { return $false }
    $p = Join-Path $target ($entry -replace '/', '\')
    return (Test-Path -LiteralPath $p)
}

function Get-Curl { return (Join-Path $env:SystemRoot 'System32\curl.exe') }

# ---------------------------------------------------------------------------
#  Launcher generation
#
#  Three tools cannot be started by running their entry point directly:
#    volatility3   writes its symbol cache under %APPDATA%\volatility3 and
#                  crashes with "unable to open database file" when that path
#                  is not writable, so the launcher redirects APPDATA.
#    theharvester  needs %USERPROFILE%\.theHarvester and .local\share created
#                  before first run, else PermissionError.
#    stegsolve     is a .jar and needs a java on PATH plus a console window.
#  The docs promise a .bat next to each of them, so they must exist after a
#  fresh clone; they used to be hand-made and therefore absent for everyone.
#
#  cmd.exe requires CRLF line endings. A BOM-less LF .bat is read as one long
#  line by cmd, which then tries to execute the words in the "rem" comments.
# ---------------------------------------------------------------------------

function Write-Launcher {
    param([string]$Path, [string]$Body)

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    # Normalise to CRLF, then write as pure ASCII. Both matter: LF breaks cmd,
    # and a non-ASCII byte in a .bat is misread under the console code page.
    $text = ($Body -replace "`r`n", "`n") -replace "`n", "`r`n"
    [System.IO.File]::WriteAllText($Path, $text, (New-Object System.Text.ASCIIEncoding))
}

function New-ToolLaunchers {
    param([string]$Root)

    $made = New-Object System.Collections.ArrayList

    # --- Volatility 3 -------------------------------------------------------
    $volDir = Join-Path $Root ($script:CatForensics + '\volatility3')
    $volBat = Join-Path $volDir ($script:LaunchPrefix + 'Volatility.bat')
    if ((Test-Path -LiteralPath $volDir) -and -not (Test-Path -LiteralPath $volBat)) {
        $body = @'
@echo off
rem Volatility 3 launcher. Generated by scripts\bootstrap.ps1 - do not edit.
rem Volatility keeps its symbol cache under %APPDATA%\volatility3; if that path
rem is not writable the plugins die with "unable to open database file". So we
rem point APPDATA at a writable cache inside the toolbox and pass --cache-path.
setlocal
cd /d "%~dp0"

rem %~dp0 is <root>\<category>\volatility3\, so go up two levels to the root.
set "VOL_DIR=%~dp0"
set "CAT_DIR=%VOL_DIR%.."
set "BOXROOT=%CAT_DIR%\.."
set "CACHE=%BOXROOT%\_box\cache"
if not exist "%CACHE%" mkdir "%CACHE%" >nul 2>&1

set "APPDATA=%CACHE%"
set "VOL=%VOL_DIR%venv\Scripts\vol.exe"

if not exist "%VOL%" (
  echo [ERROR] vol.exe not found:
  echo   %VOL%
  echo Run _box\setup.ps1 to check the environment, or
  echo   scripts\bootstrap.ps1 -Only volatility3 -Yes
  pause
  exit /b 1
)

if "%~1"=="" (
  echo Volatility 3 - interactive shell
  echo Usage: vol -f image.raw windows.info
  echo.
  cmd /k ""%VOL%" --cache-path "%CACHE%" --help"
  exit /b 0
)

"%VOL%" --cache-path "%CACHE%" %*
exit /b %ERRORLEVEL%
'@
        Write-Launcher -Path $volBat -Body $body
        [void]$made.Add($script:CatForensics + '\volatility3\' + $script:LaunchPrefix + 'Volatility.bat')
    }

    # --- theHarvester -------------------------------------------------------
    $thDir = Join-Path $Root '07-OSINT\theharvester'
    $thBat = Join-Path $thDir ($script:LaunchPrefix + 'theHarvester.bat')
    if ((Test-Path -LiteralPath $thDir) -and -not (Test-Path -LiteralPath $thBat)) {
        $body = @'
@echo off
rem theHarvester launcher. Generated by scripts\bootstrap.ps1 - do not edit.
rem theHarvester needs two writable config dirs on first run:
rem   %USERPROFILE%\.theHarvester                 (api-keys.yaml / proxies.yaml)
rem   %USERPROFILE%\.local\share\theHarvester     (stash.sqlite)
rem Without them the first run raises PermissionError.
setlocal
cd /d "%~dp0"

set "TH_DIR=%~dp0"
set "TH=%TH_DIR%venv\Scripts\theHarvester.exe"
set "CFGDIR=%USERPROFILE%\.theHarvester"
set "DBDIR=%USERPROFILE%\.local\share\theHarvester"

if not exist "%TH%" (
  echo [ERROR] theHarvester.exe not found:
  echo   %TH%
  echo Run _box\setup.ps1 to check the environment, or
  echo   scripts\bootstrap.ps1 -Only theharvester -Yes
  pause
  exit /b 1
)

if not exist "%CFGDIR%" mkdir "%CFGDIR%" >nul 2>&1
if not exist "%DBDIR%"  mkdir "%DBDIR%"  >nul 2>&1

if "%~1"=="" (
  echo theHarvester - OSINT collection
  echo Usage: theHarvester -d example.com -b duckduckgo,crtsh
  echo.
  cmd /k ""%TH%" -h"
  exit /b 0
)

"%TH%" %*
exit /b %ERRORLEVEL%
'@
        Write-Launcher -Path $thBat -Body $body
        [void]$made.Add('07-OSINT\theharvester\' + $script:LaunchPrefix + 'theHarvester.bat')
    }

    # --- StegSolve ----------------------------------------------------------
    $ssDir = Join-Path $Root 'StegSolve'
    $ssBat = Join-Path $ssDir ($script:LaunchPrefix + 'StegSolve.bat')
    $ssJar = Join-Path $ssDir 'StegSolve-1.4.jar'
    if ((Test-Path -LiteralPath $ssJar) -and -not (Test-Path -LiteralPath $ssBat)) {
        $body = @'
@echo off
rem StegSolve launcher. Generated by scripts\bootstrap.ps1 - do not edit.
rem StegSolve is a .jar, so it needs a JRE on PATH.
setlocal
cd /d "%~dp0"

set "JAR=%~dp0StegSolve-1.4.jar"

if not exist "%JAR%" (
  echo [ERROR] StegSolve-1.4.jar not found:
  echo   %JAR%
  echo Place StegSolve-1.4.jar in this folder first.
  pause
  exit /b 1
)

where java >nul 2>nul
if errorlevel 1 (
  echo [ERROR] java not found on PATH.
  echo Install a JRE/JDK 17+ and make sure "java" is on PATH.
  echo Without it StegSolve cannot start.
  pause
  exit /b 1
)

start "StegSolve" javaw -jar "%JAR%"
exit /b 0
'@
        Write-Launcher -Path $ssBat -Body $body
        [void]$made.Add('StegSolve\' + $script:LaunchPrefix + 'StegSolve.bat')
    }

    return $made
}


function Expand-Payload {
    param($tool, [string]$archivePath)

    $target = Resolve-Target $tool
    if (-not $target) { Write-Host '    no target dir, skipping extract' -ForegroundColor DarkYellow; return $true }
    if (-not (Test-Path -LiteralPath $target)) { New-Item -ItemType Directory -Path $target -Force | Out-Null }

    $sevenZip = $null
    foreach ($c in @('C:\Program Files\7-Zip\7z.exe', 'C:\Program Files (x86)\7-Zip\7z.exe',
                     (Join-Path $RepoRoot 'CTF-tools\7zip\7z.exe'), (Join-Path $RepoRoot '7z.exe'))) {
        if (Test-Path -LiteralPath $c) { $sevenZip = $c; break }
    }
    if (-not $sevenZip) {
        $cmd = Get-Command '7z' -ErrorAction SilentlyContinue
        if ($cmd) { $sevenZip = $cmd.Source }
    }

    switch ($tool.extract) {
        'zip' {
            if ($sevenZip) {
                & $sevenZip 'x' '-y' ('-o' + $target) $archivePath | Out-Null
                return ($LASTEXITCODE -eq 0)
            }
            try {
                Expand-Archive -LiteralPath $archivePath -DestinationPath $target -Force -ErrorAction Stop
                return $true
            } catch {
                Write-Host ("    7-Zip not found and Expand-Archive failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
                return $false
            }
        }
        '7z' {
            if (-not $sevenZip) { Write-Host '    7-Zip required to extract .7z' -ForegroundColor Red; return $false }
            & $sevenZip 'x' '-y' ('-o' + $target) $archivePath | Out-Null
            return ($LASTEXITCODE -eq 0)
        }
        '7z-sfx' {
            # A 7-Zip installer is itself a 7z self-extracting archive: extract, never run it.
            if (-not $sevenZip) { Write-Host '    7-Zip required to extract this SFX' -ForegroundColor Red; return $false }
            & $sevenZip 'x' '-y' ('-o' + $target) $archivePath | Out-Null
            return ($LASTEXITCODE -eq 0)
        }
        'nsis-extract' {
            # NSIS installers are valid 7z archives. Extract them, never execute:
            # running nmap's setup.exe would write registry keys and system PATH entries.
            if (-not $sevenZip) { Write-Host '    7-Zip required to extract this NSIS installer' -ForegroundColor Red; return $false }
            & $sevenZip 'x' '-y' ('-o' + $target) $archivePath | Out-Null
            return ($LASTEXITCODE -eq 0)
        }
        'tar' {
            & tar.exe -xzf $archivePath -C $target
            return ($LASTEXITCODE -eq 0)
        }
        default {
            Write-Host ("    extract mode '{0}' is manual - see docs" -f $tool.extract) -ForegroundColor DarkYellow
            return $true
        }
    }
}

function Invoke-PipTool {
    param($tool)
    $target = Resolve-Target $tool
    $mirror = $defaults.pypiMirror

    # Prefer an explicit Python 3.12 base when the toolbox layout is in use.
    $basePy = $null
    $pyCandidates = @()
    foreach ($d in @('pythoncore-3.12-64','pythoncore-3.13-64','pythoncore-3.14-64')) {
        $pyCandidates += (Join-Path $env:LOCALAPPDATA ('Python\' + $d + '\python.exe'))
    }
    foreach ($c in $pyCandidates) {
        if (Test-Path -LiteralPath $c) { $basePy = $c; break }
    }
    if (-not $basePy) {
        $cmd = Get-Command 'python' -ErrorAction SilentlyContinue
        if ($cmd) { $basePy = $cmd.Source }
    }
    if (-not $basePy) {
        Write-Host '    Python not found; install Python 3.10+ first' -ForegroundColor Red
        return $false
    }

    $venvPy = Join-Path $target 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPy)) {
        Write-Host ("    creating venv: {0}" -f $target) -ForegroundColor DarkGray
        & $basePy -m venv $target
        if ($LASTEXITCODE -ne 0) { Write-Host '    venv creation failed' -ForegroundColor Red; return $false }
    }

    $spec = $tool.url
    if ($spec -match '^pip:(.+)$') { $spec = $Matches[1] }

    Write-Host ("    pip install {0}" -f $spec) -ForegroundColor DarkGray
    & $venvPy -m pip install --no-cache-dir --disable-pip-version-check -i $mirror $spec
    return ($LASTEXITCODE -eq 0)
}

# ---------------------------------------------------------------------------
#  binwalk Windows compatibility patch
#
#  binwalk 2.3.4 is POSIX-only. Without this patch "-e" dies before carving a
#  single byte:
#
#    os.getuid()  -> extractor.py:143   AttributeError: no attribute 'getuid'
#    os.chown()   -> extractor.py:580/876
#    os.fork/setuid/setgid -> extractor.py:964-991 (only with --run-as)
#
#  Scanning (no -e) never touches those lines, which is why plain scans look
#  fine. Three files fix it:
#
#    Lib/site-packages/sitecustomize.py   auto-imported by CPython's site
#                                         module, so it survives `pip install -U`
#    _winconfig/binwalk/config/extract.conf  Windows rules (7-Zip / jar / tar)
#    binwalk.bat                          launcher: UTF-8 + XDG_CONFIG_HOME
#
#  All three bodies below are pure ASCII on purpose. This script must stay
#  ASCII too, so the payloads are written verbatim rather than transcoded.
# ---------------------------------------------------------------------------

$script:BinwalkSiteCustomize = @'
"""Windows compatibility shims for binwalk's POSIX-only code paths.

binwalk 2.3.4 assumes POSIX. Two of its assumptions are fatal on Windows:

  1. ``binwalk/modules/extractor.py`` calls ``os.getuid()`` while the extractor
     module loads. ``os`` on Windows has no ``getuid``, so ``-e`` dies with
     ``AttributeError: module 'os' has no attribute 'getuid'`` before a single
     byte is carved. Scanning (without -e) never touches that line, which is
     why plain scans work.
  2. ``build_output_directory()`` and ``_dd()`` call ``os.chown()``. Also
     absent on Windows, so extraction dies again even after (1) is fixed.

Both are privilege-dropping features ("run extractors as another user") with
no Windows equivalent. We report a fixed non-zero uid so binwalk never thinks
it is root (uid 0 triggers its "do not extract as root" guard), and turn the
ownership calls into no-ops.

The ``if self.runas_uid != os.getuid()`` branch in ``shell_call()`` therefore
compares equal and the ``os.fork()`` privilege-switch path stays dead, so no
fork/setuid/setgid shims are needed. They are defined anyway as no-ops so a
stray call cannot crash the run.

This file is auto-imported by CPython's ``site`` module at startup, so it
applies to every ``binwalk.bat`` invocation without patching site-packages
files that ``pip install -U binwalk`` would overwrite.

Generated by scripts/bootstrap.ps1 - do not edit.
"""

import os

_FIXED_UID = 1000  # never 0: binwalk treats uid 0 as root and refuses to extract


def _install() -> None:
    def _noop(*args, **kwargs):
        return None

    # --- identity -------------------------------------------------------
    if not hasattr(os, "getuid"):
        os.getuid = lambda: _FIXED_UID
    if not hasattr(os, "geteuid"):
        os.geteuid = lambda: _FIXED_UID
    if not hasattr(os, "getgid"):
        os.getgid = lambda: _FIXED_UID
    if not hasattr(os, "getegid"):
        os.getegid = lambda: _FIXED_UID

    # --- privilege dropping (no-op: already running as the right user) ---
    for name in ("setuid", "seteuid", "setgid", "setegid", "chown", "lchown"):
        if not hasattr(os, name):
            setattr(os, name, _noop)

    # NOTE: do NOT define os.fork. Python's stdlib random module does
    # ``if hasattr(_os, "fork"): _os.register_at_fork(...)``, and Windows
    # has no register_at_fork -- faking fork breaks every `import random`
    # (and therefore email, importlib.metadata, and binwalk itself).
    # Without fork, the uid comparison above keeps that branch unreachable.


_install()
'@

$script:BinwalkExtractConf = @'
########################################################################################
# Windows extraction rules for binwalk.
#
# binwalk's bundled extract.conf targets Linux: gzip, unzip, 7z, tar, unrar,
# unsquashfs, jefferson ... none of which are on PATH here. Running -e as-is
# makes every rule fail with "WinError 2 the system cannot find the file",
# leaving only the built-in zlib / gzip plugins able to do anything.
#
# This file re-declares the rules using tools this machine actually has.
# binwalk loads the user-level config before the system-level one and the
# first matching rule wins, so the zip / tar rules below override the bundled
# Linux ones.
#
# This file is installed by scripts/bootstrap.ps1 and located via the
# XDG_CONFIG_HOME that binwalk.bat sets, so nothing is written to the user's
# home directory and the toolbox stays portable.
#
# Format: <regex matching binwalk output description>:<extension>:<command>:<ok codes>:<recurse>
# %e is the file dd'd out of the carrier. Paths are single-quoted because
# binwalk splits commands with shlex, and a single-quoted backslash survives.
########################################################################################

# ---------------------------------------------------------------- compressed streams
# The built-in gzip plugin already handles "gzip compressed data" in pure
# Python (gzipextract.py), so it is not re-declared here. The built-in lzma
# plugin handles raw LZMA. xz / bz2 / compress / lzo go to 7-Zip.
^xz compressed data:xz:7z x -y -o"%e.out" '%e':0,1
^bzip2 compressed data:bz2:7z x -y -o"%e.out" '%e':0,1
^compress'd data:Z:7z x -y -o"%e.out" '%e':0,1
^lzop compressed data:lzo:7z x -y -o"%e.out" '%e':0,1

# ---------------------------------------------------------------- archives
# zip tries jar first (ships with the JDK and is more tolerant of a truncated
# or damaged central directory than 7-Zip), then falls back to 7-Zip.
^zip archive data:zip:jar xvf '%e':0
^zip archive data:zip:7z x -y -o"%e.out" '%e':0,1

# tar: Windows 10+ ships C:\Windows\System32\tar.exe, which natively reads
# gz / bz2 / xz wrapped tars as well as plain tar.
^posix tar archive:tar:tar xf '%e':0
^gnu tar archive:tar:tar xf '%e':0

# rar / 7z / iso / cab: all handled by 7-Zip.
^rar archive data:rar:7z x -y -o"%e.out" '%e':0,1
^7-zip archive data:7z:7z x -y -o"%e.out" '%e':0,1
^iso 9660:iso:7z x -y -o"%e.out" '%e':0,1
^microsoft cabinet archive:cab:7z x -y -o"%e.out" '%e':0,1
^microsoft executable:cab:7z x -y -o"%e.out" '%e':0,1

# ---------------------------------------------------------------- firmware filesystems
# unsquashfs / jefferson / ubireader / cramfsck are Linux-only and have no
# Windows counterpart. The rule is kept but the command is dropped: binwalk
# still carves the whole region out, so it can be handled by hand with 7-Zip,
# WSL, or a dedicated tool. An empty command stops binwalk at the carve step.
^squashfs filesystem:squashfs
^cramfs filesystem:cramfs
^jffs2 filesystem:jffs2
^ubifs filesystem:ubi
^ubi erase count header:ubi
^yaffs filesystem:yaffs
^romfs filesystem:romfs
^linux ext:ext
^linux ext filesystem:ext2

# ---------------------------------------------------------------- carve only
# ELF / keys / certificates / text have no usable external unpacker; carving
# the bytes out is all that is wanted.
^elf,
^private key:key
^certificate:crt
^xml document:xml
^html document header:html
'@

$script:BinwalkLauncher = @'
@echo off
rem binwalk launcher for Windows. Generated by scripts\bootstrap.ps1 - do not edit.
rem
rem 1) Runs binwalk inside its dedicated virtual environment with UTF-8 output so
rem    that non-ASCII paths (e.g. Chinese filenames) work correctly.
rem 2) Points XDG_CONFIG_HOME at _winconfig so binwalk loads our Windows-specific
rem    extract.conf (the bundled one shells out to unzip/7z/tar/unrar which are
rem    not on PATH here). Keeping it out of %USERPROFILE% keeps the toolbox
rem    self-contained and portable.
rem 3) Prepends the real extractor tools this machine has: 7-Zip and the JDK jar.
rem    Windows' own tar.exe is already in PATH.
setlocal
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
set "XDG_CONFIG_HOME=%~dp0_winconfig"
set "PATH=C:\Program Files\7-Zip;C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot\bin;%PATH%"
"%~dp0..\binwalk\Scripts\python.exe" -X utf8 -m binwalk %*
exit /b %ERRORLEVEL%
'@

function Write-AsciiFile {
    param([string]$Path, [string]$Body)

    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $text = ($Body -replace "`r`n", "`n") -replace "`n", "`r`n"
    [System.IO.File]::WriteAllText($Path, $text, (New-Object System.Text.ASCIIEncoding))
}

function Repair-Binwalk {
    param([string]$Root, [string]$Target)

    $changed = New-Object System.Collections.ArrayList
    $venvPy = Join-Path $Target 'Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPy)) {
        Write-Host '    venv missing; run pip install first' -ForegroundColor Red
        return $changed
    }

    # --- 1. sitecustomize.py: the os.getuid / os.chown shims -----------------
    # Ask the venv where its site-packages is, but read the answer from a file
    # rather than stdout: under a Chinese install path the console code page
    # mangles a path printed by Python, so a captured string would not exist on
    # disk. sysconfig.get_path('purelib') is also more reliable than
    # site.getsitepackages(), which returns the venv root for some layouts.
    $probeOut = Join-Path ([System.IO.Path]::GetTempPath()) ('mbw-sp-' + [guid]::NewGuid().ToString('N') + '.txt')
    & $venvPy -c "import sysconfig,io;io.open(r'$probeOut','w',encoding='utf-8').write(sysconfig.get_path('purelib'))" 2>$null
    $sp = $null
    if (Test-Path -LiteralPath $probeOut) {
        $sp = (Get-Content -LiteralPath $probeOut -Raw -Encoding UTF8).Trim()
        Remove-Item -LiteralPath $probeOut -Force -ErrorAction SilentlyContinue
    }
    if (-not $sp -or -not (Test-Path -LiteralPath $sp)) {
        Write-Host '    could not locate site-packages' -ForegroundColor Red
        return $changed
    }
    $scPath = Join-Path $sp 'sitecustomize.py'
    # An unrelated sitecustomize.py may already exist; never clobber it blindly.
    if ((Test-Path -LiteralPath $scPath) -and
        -not (Select-String -LiteralPath $scPath -Pattern 'binwalk' -Quiet -ErrorAction SilentlyContinue)) {
        Write-Host '    sitecustomize.py exists and is not ours; skipping' -ForegroundColor DarkYellow
    } else {
        Write-AsciiFile -Path $scPath -Body $script:BinwalkSiteCustomize
        [void]$changed.Add('sitecustomize.py')
    }

    # --- 2. extract.conf: Windows rules --------------------------------------
    $cfgDir = Join-Path (Join-Path $Target '_winconfig') 'binwalk\config'
    $exPath = Join-Path $cfgDir 'extract.conf'
    Write-AsciiFile -Path $exPath -Body $script:BinwalkExtractConf
    [void]$changed.Add('_winconfig\binwalk\config\extract.conf')

    # binwalk creates the magic dir itself; an empty file keeps the settings
    # code from complaining about a missing user config tree.
    $mgPath = Join-Path (Join-Path $Target '_winconfig') 'binwalk\magic\binarch'
    if (-not (Test-Path -LiteralPath $mgPath)) {
        Write-AsciiFile -Path $mgPath -Body ''
    }

    # --- 3. binwalk.bat: UTF-8 + XDG_CONFIG_HOME + tool PATH -----------------
    $batPath = Join-Path $Target 'binwalk.bat'
    Write-AsciiFile -Path $batPath -Body $script:BinwalkLauncher
    [void]$changed.Add('binwalk.bat')

    # --- 4. verify: -e must get past module load -----------------------------
    # A cheap import-only probe: it fails with AttributeError on the unpatched
    # tree and returns cleanly once sitecustomize is in place.
    $probe = & $venvPy -c "import os;os.getuid()" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ("    patch did not take effect: {0}" -f ($probe -join ' ')) -ForegroundColor Red
    } else {
        Write-Host '    patch verified (os.getuid available)' -ForegroundColor DarkGray
    }

    return $changed
}

# ---------------------------------------------------------------------------
#  Report current state
# ---------------------------------------------------------------------------

$rows = New-Object System.Collections.ArrayList
foreach ($t in $manifest.tools) {
    if ($onlyIds.Count -gt 0 -and ($onlyIds -notcontains $t.id)) { continue }
    [void]$rows.Add([pscustomobject]@{
        id        = $t.id
        name      = $t.name
        version   = $t.version
        category  = $t.category
        installed = (Test-Installed $t)
        auto      = $t.auto
        tool      = $t
    })
}

# Launchers are generated on every run, before any early exit, because a tool
# may have been fetched by hand and the docs promise these .bat files exist.
# Missing them is what makes the GUI show a red dot for an installed tool.
$newLaunchers = @(New-ToolLaunchers -Root $RepoRoot)
if ($newLaunchers.Count -gt 0 -and -not $Json) {
    Write-Host ''
    Write-Host 'Generated launchers:' -ForegroundColor Cyan
    foreach ($l in $newLaunchers) { Write-Host ("  + {0}" -f $l) -ForegroundColor Green }
}

if ($Json) {
    ($rows | Select-Object id, name, version, category, installed, auto | ConvertTo-Json -Depth 3)
    exit 0
}

Write-Host ''
Write-Host '============== MiscBox tools status ==============' -ForegroundColor Cyan
foreach ($r in $rows) {
    $mark = if ($r.installed) { 'OK  ' } else { 'MISS' }
    $color = if ($r.installed) { 'Green' } else { 'Yellow' }
    $flag = if ($r.auto) { '' } else { '  [manual]' }
    Write-Host ("  [{0}] {1,-28} {2,-16}{3}" -f $mark, $r.name, $r.version, $flag) -ForegroundColor $color
}
$missingAuto = @($rows | Where-Object { -not $_.installed -and $_.auto })
$missingManual = @($rows | Where-Object { -not $_.installed -and -not $_.auto })
Write-Host '==================================================' -ForegroundColor Cyan
Write-Host ("  installed {0} / {1}   auto-downloadable missing: {2}   manual: {3}" -f `
    @($rows | Where-Object { $_.installed }).Count, $rows.Count, $missingAuto.Count, $missingManual.Count)
Write-Host ''

if ($missingManual.Count -gt 0) {
    Write-Host 'These need manual acquisition (license or build step):' -ForegroundColor DarkYellow
    foreach ($m in $missingManual) {
        Write-Host ("  - {0}: {1}" -f $m.name, $m.tool.note) -ForegroundColor DarkYellow
    }
    Write-Host ''
}

if (-not $Interactive -and -not $Yes) {
    Write-Host 'Nothing downloaded. Re-run with:' -ForegroundColor Gray
    Write-Host '  -Interactive   ask before each download' -ForegroundColor Gray
    Write-Host '  -Yes           download all auto tools without asking' -ForegroundColor Gray
    Write-Host '  -Only id,id    limit to specific tools' -ForegroundColor Gray
    exit 0
}

# ---------------------------------------------------------------------------
#  Download
# ---------------------------------------------------------------------------

$queue = @()
if ($Yes) {
    $queue = $missingAuto
} else {
    foreach ($r in $missingAuto) {
        $t = $r.tool
        $sizeNote = ''
        Write-Host ("Download {0} {1}?" -f $r.name, $r.version) -ForegroundColor White
        if ($t.note) { Write-Host ("  {0}" -f $t.note) -ForegroundColor DarkGray }
        if ($t.url) { Write-Host ("  {0}" -f $t.url) -ForegroundColor DarkGray }
        $ans = Read-Host '  [y/N]'
        if ($ans -match '^(y|Y)') { $queue += $r }
    }
}

if ($queue.Count -eq 0) {
    Write-Host ''
    Write-Host 'Nothing selected.' -ForegroundColor Gray
    exit 0
}

Write-Host ''
$failed = New-Object System.Collections.ArrayList
foreach ($r in $queue) {
    $t = $r.tool
    Write-Host ''
    Write-Host ("=== {0} {1} ===" -f $r.name, $r.version) -ForegroundColor Cyan

    if ($t.extract -eq 'pip' -or $t.extract -eq 'pip-src') {
        $okPip = Invoke-PipTool $t
        if (-not $okPip) {
            [void]$failed.Add($r.name)
        } elseif ($t.id -eq 'binwalk') {
            # binwalk is POSIX-only upstream: -e crashes on Windows until this
            # patch is applied. It is applied on every install, so `pip install
            # -U binwalk` cannot silently reintroduce the bug.
            $bwTarget = Resolve-Target $t
            if ($bwTarget) {
                Write-Host '  applying Windows compatibility patch...' -ForegroundColor DarkGray
                $bwFixed = Repair-Binwalk -Root $RepoRoot -Target $bwTarget
                foreach ($c in $bwFixed) { Write-Host ("    wrote {0}" -f $c) -ForegroundColor DarkGray }
            }
        }
        continue
    }

    if (-not $t.url) {
        Write-Host '  no download URL (manual tool)' -ForegroundColor DarkYellow
        [void]$failed.Add($r.name)
        continue
    }

    $dlDir = Join-Path $RepoRoot $defaults.downloadDir
    if (-not (Test-Path -LiteralPath $dlDir)) { New-Item -ItemType Directory -Path $dlDir -Force | Out-Null }
    $archive = Join-Path $dlDir $t.asset

    $fetchArgs = @('-Url', $t.url, '-Out', $archive, '-Retries', $defaults.retries, '-Proxy')
    if ($t.sha256) { $fetchArgs += @('-Sha256', $t.sha256) }
    & powershell -NoProfile -ExecutionPolicy Bypass -File $Fetch @fetchArgs
    if ($LASTEXITCODE -ne 0) {
        [void]$failed.Add($r.name)
        continue
    }

    Write-Host '  extracting...' -ForegroundColor DarkGray
    $okX = Expand-Payload $t $archive
    if (-not $okX) { [void]$failed.Add($r.name); continue }

    # Post-extract fixups for archives whose shipped layout differs from the
    # name the tool is actually used under.
    $target = Resolve-Target $t
    if ($target -and (Test-Path -LiteralPath $target)) {
        # ExifTool ships its launcher as "exiftool(-k).exe"; upstream tells users
        # to rename it to exiftool.exe. Rename it wherever it currently sits,
        # before flattening, because the flatten step looks for the final name.
        if ($t.id -eq 'exiftool') {
            foreach ($dir in @($target) + @(Get-ChildItem -LiteralPath $target -Directory -Force |
                                            ForEach-Object { $_.FullName })) {
                $k = Join-Path $dir 'exiftool(-k).exe'
                $plain = Join-Path $dir 'exiftool.exe'
                if ((Test-Path -LiteralPath $k) -and -not (Test-Path -LiteralPath $plain)) {
                    Move-Item -LiteralPath $k -Destination $plain -Force
                    Write-Host '  renamed exiftool(-k).exe -> exiftool.exe' -ForegroundColor DarkGray
                }
            }
        }

        # Flatten nested directories until the entry point sits at the target root.
        # Archives often wrap everything in one folder whose name carries the
        # version (exiftool-13.59_64/, john-1.9.0-jumbo-1-win64/), and sometimes
        # that folder lands inside the target instead of replacing it.
        if ($t.entry) {
            for ($depth = 0; $depth -lt 4; $depth++) {
                $entryPath = Join-Path $target ($t.entry -replace '/', '\')
                if (Test-Path -LiteralPath $entryPath) { break }

                $subDirs = @(Get-ChildItem -LiteralPath $target -Directory -Force)
                $files = @(Get-ChildItem -LiteralPath $target -File -Force)
                if ($subDirs.Count -ne 1 -or $files.Count -gt 1) { break }

                $inner = $subDirs[0].FullName
                $innerEntry = Join-Path $inner ($t.entry -replace '/', '\')
                if (-not (Test-Path -LiteralPath $innerEntry)) { break }

                Write-Host ("  flattening {0}" -f $subDirs[0].Name) -ForegroundColor DarkGray
                Get-ChildItem -LiteralPath $inner -Force | Move-Item -Destination $target -Force
                Remove-Item -LiteralPath $inner -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    if (Test-Installed $t) {
        Write-Host '  verified entry point present' -ForegroundColor Green
    } else {
        Write-Host ("  entry point not found: {0}" -f $t.entry) -ForegroundColor Yellow
        Write-Host '  the archive layout may differ; check the folder manually' -ForegroundColor DarkYellow
    }
}

Write-Host ''
Write-Host '============== summary ==============' -ForegroundColor Cyan
if ($failed.Count -eq 0) {
    Write-Host '  all selected tools installed' -ForegroundColor Green
} else {
    Write-Host '  failed:' -ForegroundColor Red
    foreach ($f in $failed) { Write-Host ("   - {0}" -f $f) -ForegroundColor Red }
}

Write-Host ''
Write-Host 'Next: run the environment check' -ForegroundColor Gray
Write-Host '  powershell -NoProfile -ExecutionPolicy Bypass -File _box\setup.ps1' -ForegroundColor Gray
Write-Host 'Then: double-click the launcher in _box\' -ForegroundColor Gray
exit 0





