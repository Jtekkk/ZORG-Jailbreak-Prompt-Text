@echo off
title WinDiag Pro - Build Script
echo ============================================================
echo  WinDiag Pro - Build EXE
echo ============================================================
echo.

:: Check Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python not found. Install Python 3.10+ and add to PATH.
    pause
    exit /b 1
)

:: Install dependencies
echo [1/3] Installing dependencies...
pip install -r requirements.txt --quiet
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

:: Install PyInstaller
pip install pyinstaller --quiet

:: Build executable
echo [2/3] Building executable...
pyinstaller --onefile ^
    --windowed ^
    --name "WinDiagPro" ^
    --icon NONE ^
    --add-data "scanner.py;." ^
    --add-data "fixer.py;." ^
    --hidden-import customtkinter ^
    --hidden-import psutil ^
    --hidden-import winreg ^
    --collect-all customtkinter ^
    windiag.py

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed.
    pause
    exit /b 1
)

echo [3/3] Done!
echo.
echo Output: dist\WinDiagPro.exe
echo.
echo To run with administrator privileges right-click the exe
echo and select "Run as administrator" for full functionality.
echo ============================================================
pause
