@echo off
rem ============================================================
rem  envcheck.bat -- launcher for envcheck.py
rem  Double-click to check what this machine is missing.
rem  NOTE: keep this file pure ASCII -- cmd.exe parses .bat
rem        using the OEM codepage, so Chinese text here would
rem        be mangled. All Chinese output comes from Python.
rem ============================================================
setlocal
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

rem ---- locate Python ----
rem  Probe order: box venv -> launcher-adjacent copy -> common
rem  installs -> PATH. No user-specific hardcoded path here.
set "PY="
if exist "%~dp0..\..\_box\venv\Scripts\python.exe" set "PY=%~dp0..\..\_box\venv\Scripts\python.exe"
if not defined PY if exist "%~dp0python.exe" set "PY=%~dp0python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe" set "PY=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Python\pythoncore-3.13-64\python.exe" set "PY=%LOCALAPPDATA%\Python\pythoncore-3.13-64\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Python\pythoncore-3.12-64\python.exe" set "PY=%LOCALAPPDATA%\Python\pythoncore-3.12-64\python.exe"
if not defined PY if exist "C:\Python313\python.exe" set "PY=C:\Python313\python.exe"
if not defined PY if exist "C:\Python312\python.exe" set "PY=C:\Python312\python.exe"
if not defined PY if exist "C:\Python311\python.exe" set "PY=C:\Python311\python.exe"
if not defined PY if exist "C:\Python310\python.exe" set "PY=C:\Python310\python.exe"
if not defined PY for %%i in (python.exe) do if exist "%%~$PATH:i" set "PY=%%~$PATH:i"
if not defined PY for %%i in (python3.exe) do if exist "%%~$PATH:i" set "PY=%%~$PATH:i"
if not defined PY (
    echo [ERROR] Python not found.
    echo.
    echo   Install Python 3.9+ and make sure it is on PATH,
    echo   or run _box\setup.ps1 once to let the toolbox find it.
    echo.
    echo   You can also edit this .bat and set PY manually.
    if not defined ENVCHECK_NO_PAUSE pause
    exit /b 1
)

rem ---- arguments given: forward them all ----
if not "%~1"=="" (
    "%PY%" -X utf8 "%~dp0envcheck.py" %*
    set "RC=%ERRORLEVEL%"
    if defined ENVCHECK_NO_PAUSE exit /b %RC%
    echo.
    echo Press any key to close...
    pause >nul
    exit /b %RC%
)

rem ---- no argument: run the check, then keep the window open ----
"%PY%" -X utf8 "%~dp0envcheck.py"
set "RC=%ERRORLEVEL%"
echo.
if defined ENVCHECK_NO_PAUSE exit /b %RC%
echo Press any key to close...
pause >nul
exit /b %RC%
