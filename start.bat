@echo off
rem Squidbrake for Windows: double-click this file, or run "start.bat --port 9000".
rem The first run installs everything into .venv. Squidbrake then runs in the background and starts again at every
rem login; "start.bat --foreground" runs it in this window instead. Stop it: .venv\Scripts\python service.py stop
setlocal
cd /d "%~dp0"
title Squidbrake

if exist ".venv\Scripts\python.exe" goto deps
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY goto nopython
echo Setting up Squidbrake (first run only, takes a minute)...
%PY% -m venv .venv
if errorlevel 1 (
  if exist .venv rmdir /s /q .venv
  goto nopython
)

:deps
rem Reinstall only when requirements.txt has changed since the last install.
fc /b requirements.txt .venv\installed.txt >nul 2>nul && goto run
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 (
  echo.
  echo Installing dependencies failed. Check your internet connection and run start.bat again.
  pause
  exit /b 1
)
copy /y requirements.txt .venv\installed.txt >nul

:run
".venv\Scripts\python.exe" service.py start %*
if errorlevel 1 pause
if not errorlevel 1 timeout /t 8
exit /b

:nopython
echo.
echo Python 3.10 or newer is needed. Get it from https://www.python.org/downloads/
echo (tick "Add python.exe to PATH" during install), then run start.bat again.
pause
exit /b 1
