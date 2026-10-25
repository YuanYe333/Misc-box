@echo off
rem MiscBox launcher - finds a usable Python and starts the GUI.
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "PY="
rem 1) bundled/known Python 3.14
if exist "C:\Users\%USERNAME%\AppData\Local\Python\pythoncore-3.14-64\python.exe" (
  set "PY=C:\Users\%USERNAME%\AppData\Local\Python\pythoncore-3.14-64\python.exe"
)
rem 2) fall back to python on PATH
if not defined PY (
  for /f "delims=" %%i in ('where python 2^>nul') do (
    if not defined PY set "PY=%%i"
  )
)

if not defined PY (
  echo [ERROR] Python not found.
  echo Install Python 3.10+ or run _box\setup.ps1 for a check.
  pause
  exit /b 1
)

rem tkinter is required by the GUI
"%PY%" -c "import tkinter" >nul 2>&1
if errorlevel 1 (
  echo [ERROR] This Python has no tkinter support:
  echo   %PY%
  echo Use another Python 3.x build with Tk.
  pause
  exit /b 1
)

"%PY%" -X utf8 "app\gui.py"
if errorlevel 1 (
  echo.
  echo [ERROR] GUI exited with an error. See the message above.
  pause
)
exit /b 0
