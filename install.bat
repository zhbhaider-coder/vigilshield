@echo off
REM ============================================================
REM  VigilShield installer (v2)
REM  Usage:  install.bat          -> install
REM          install.bat uninstall -> remove everything
REM ============================================================
setlocal

set APPDIR=%LOCALAPPDATA%\VigilShield
set EXE=VigilShield.exe

if /i "%~1"=="uninstall" goto :uninstall

:install
echo === Installing VigilShield ===
echo.

if not exist "%~dp0%EXE%" (
    echo ERROR: %EXE% not found next to this installer.
    echo Put install.bat in the same folder as %EXE% and run again.
    pause
    exit /b 1
)

echo [1/4] Copying files to %APPDIR%...
if not exist "%APPDIR%" mkdir "%APPDIR%"
copy /y "%~dp0%EXE%" "%APPDIR%\%EXE%" >nul
if errorlevel 1 (
    echo ERROR: could not copy. Try running install.bat as administrator.
    pause
    exit /b 1
)

echo [2/4] Creating Start Menu shortcut...
powershell -NoProfile -Command ^
  "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%APPDATA%\Microsoft\Windows\Start Menu\Programs\VigilShield.lnk');" ^
  "$s.TargetPath='%APPDIR%\%EXE%';" ^
  "$s.WorkingDirectory='%APPDIR%';" ^
  "$s.Description='VigilShield PC Guard';" ^
  "$s.Save()"

echo [3/4] Registering auto-start at logon...
schtasks /create /tn "VigilShield" /tr "'%APPDIR%\%EXE%'" /sc onlogon /rl limited /f >nul 2>&1
if errorlevel 1 echo      (auto-start task needs administrator - continuing anyway)

echo [4/4] Scheduling daily exposure scan (09:00)...
schtasks /create /tn "VigilShield Daily Scan" /tr "'%APPDIR%\%EXE%' --exposure-scan" /sc daily /st 09:00 /rl limited /f >nul 2>&1
if errorlevel 1 echo      (daily scan task needs administrator - continuing anyway)

echo.
echo === DONE ===
echo VigilShield is installed. Find it in your Start Menu.
echo Right-click it and choose "Run as administrator" for full protection.
echo To remove: run  install.bat uninstall
pause
exit /b 0

:uninstall
echo === Uninstalling VigilShield ===
echo.

if exist "%APPDIR%\%EXE%" (
    echo Removing firewall rules added by VigilShield...
    "%APPDIR%\%EXE%" --uninstall-rules
)

echo Removing scheduled tasks...
schtasks /delete /tn "VigilShield" /f >nul 2>&1
schtasks /delete /tn "VigilShield Daily Scan" /f >nul 2>&1

echo Removing Start Menu shortcut...
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\VigilShield.lnk" >nul 2>&1

echo Removing program folder...
rmdir /s /q "%APPDIR%" >nul 2>&1

echo.
echo === DONE === VigilShield has been removed.
echo Your Windows Firewall rules added by VigilShield were deleted.
pause
exit /b 0
