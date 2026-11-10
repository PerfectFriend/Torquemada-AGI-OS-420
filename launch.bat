@echo off
set PATH=%PATH%;%USERPROFILE%\.cargo\bin
cd /d "%~dp0app"
if exist "src-tauri\target\release\w420.exe" (start "" "src-tauri\target\release\w420.exe") else (npm run tauri dev)
