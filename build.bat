@echo off
REM VigilShield build script - double-click this file on Windows.
REM 1. Installs Python dependencies
REM 2. Builds a single VigilShield.exe with PyInstaller
echo === VigilShield build ===
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python is not installed.
    echo Download it from https://www.python.org/downloads/ and tick
    echo "Add python.exe to PATH" during install, then run this again.
    pause
    exit /b 1
)

echo Installing dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: could not install dependencies.
    pause
    exit /b 1
)

echo.
echo Building VigilShield.exe (this takes a few minutes)...
python -m PyInstaller --onefile --windowed --name VigilShield ^
    --icon "vigilshield\data\mascot.ico" ^
    --add-data "vigilshield\data;vigilshield\data" ^
    --hidden-import psutil --hidden-import pystray --hidden-import PIL ^
    -p . ^
    vigilshield\ui.py

if errorlevel 1 (
    echo ERROR: build failed.
    pause
    exit /b 1
)

echo.
echo === DONE ===
echo Your file is at: dist\VigilShield.exe
echo Copy it anywhere, right-click it and choose "Run as administrator".
pause
