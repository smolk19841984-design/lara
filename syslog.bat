@echo off
setlocal EnableExtensions
chcp 65001 >nul

set "BASE_DIR=%~dp0"
set "TOOLS_EXE=%BASE_DIR%tools\idevicesyslog.exe"
set "LOG_DIR=%BASE_DIR%log"
set "MODE=%~1"

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

for /f %%i in ('powershell -NoProfile -Command "(Get-Date).ToString('yyyyMMdd_HHmmss')"') do set "TS=%%i"
set "LOG_FILE=%LOG_DIR%\lara_syslog_%TS%.log"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$enc = New-Object System.Text.UTF8Encoding($false); [System.IO.File]::WriteAllText($env:LOG_FILE, ('Lara syslog started: ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + [Environment]::NewLine), $enc)"

echo =======================================
echo Lara Live Syslog Monitor
echo Waiting for device syslog...
if /I "%MODE%"=="full" (
echo Mode: FULL (all device lines)
) else (
echo Mode: Lara process only (all Lara lines)
)
echo Press Ctrl+C to stop.
echo Saving to: %LOG_FILE%
echo =======================================

if not exist "%TOOLS_EXE%" (
    echo [ERROR] File not found: %TOOLS_EXE%
    pause
    exit /b 1
)

if /I "%MODE%"=="full" (
powershell -NoProfile -ExecutionPolicy Bypass -Command "$exe = $env:TOOLS_EXE; $log = $env:LOG_FILE; $enc = New-Object System.Text.UTF8Encoding($false); & $exe 2>&1 | ForEach-Object { $line = [string]$_; Write-Host $line; [System.IO.File]::AppendAllText($log, $line + [Environment]::NewLine, $enc) }"
) else (
powershell -NoProfile -ExecutionPolicy Bypass -Command "$exe = $env:TOOLS_EXE; $log = $env:LOG_FILE; $enc = New-Object System.Text.UTF8Encoding($false); $proc = '^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+lara(\([^\)]*\))?\[[0-9]+\]'; & $exe 2>&1 | Where-Object { $_ -match $proc } | ForEach-Object { $line = [string]$_; Write-Host $line; [System.IO.File]::AppendAllText($log, $line + [Environment]::NewLine, $enc) }"
)

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] idevicesyslog command failed.
    echo Make sure "idevicesyslog.exe" is located in the "tools" folder.
)
pause
