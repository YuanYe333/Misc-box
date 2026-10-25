@echo off
rem ============================================================
rem  usbhid.bat -- launcher for usbhid.py
rem  Drag a file or a folder onto this file to run it.
rem  NOTE: keep this file pure ASCII -- cmd.exe parses .bat
rem        using the OEM codepage, so Chinese text here would
rem        be mangled. All Chinese output comes from Python.
rem ============================================================
setlocal
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

rem ---- locate Python ----
rem  Probe order: launcher-adjacent copy -> box venv -> common installs
rem  -> PATH. No user-specific hardcoded path here on purpose.
set "PY="
if exist "%~dp0..\..\_box\venv\Scripts\python.exe" set "PY=%~dp0..\..\_box\venv\Scripts\python.exe"
if not defined PY if exist "%~dp0python.exe" set "PY=%~dp0python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
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
    if not defined USBHID_NO_PAUSE pause
    exit /b 1
)

rem ---- no argument: show usage ----
if "%~1"=="" goto USAGE

rem ---- arguments given: forward them all ----
"%PY%" -X utf8 "%~dp0usbhid.py" %*
set "RC=%ERRORLEVEL%"
if defined USBHID_NO_PAUSE exit /b %RC%
echo.
echo Press any key to close...
pause >nul
exit /b %RC%

:USAGE
echo.
echo    USB HID keyboard/mouse decoder
echo    ==============================
echo.
echo    Decode usbmon / USBPcap HID reports into keystrokes and mouse path.
echo    Handles Shift/Ctrl and draws the mouse trail as PNG.
echo.
echo    How to use:
echo      1^) Drag a file or a folder onto this .bat
echo      2^) Or run from a command line:
echo           usbhid.bat "D:\path\to\target"
echo.
echo    For full options:  usbhid.bat --help
echo.
set "TARGET="
set /p "TARGET=   Paste a path here (or press Enter to quit): "
if not defined TARGET exit /b 0
"%PY%" -X utf8 "%~dp0usbhid.py" "%TARGET%"
echo.
if not defined USBHID_NO_PAUSE pause
exit /b 0
