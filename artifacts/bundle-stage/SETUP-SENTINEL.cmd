@echo off
setlocal
title Sentinel one-click setup
set "SETUP=%~dp0sentinel\windows\setup-sentinel.ps1"
if not exist "%SETUP%" (
  echo.
  echo Could not find:
  echo   %SETUP%
  echo.
  echo Extract the whole zip first, then double-click this file from that folder.
  echo.
  pause
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SETUP%"
exit /b %errorlevel%
