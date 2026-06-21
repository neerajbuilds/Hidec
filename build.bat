@echo off
setlocal enabledelayedexpansion
echo ============================================================
echo   Hidec 2026 ^| Windows Build Script
echo ============================================================
echo.

:: Check for py launcher (Python 3.14 uses 'py' on Windows)
where py >nul 2>&1
if not errorlevel 1 (
    set PY=py
    goto :found_python
)
where python >nul 2>&1
if not errorlevel 1 (
    set PY=python
    goto :found_python
)
echo ERROR: Python not found.
echo Install Python 3.11+ from https://python.org and check "Add to PATH".
pause & exit /b 1

:found_python
echo [1/4] Python found: using "%PY%"
%PY% --version
echo.

echo [2/4] Installing / upgrading dependencies...
%PY% -m pip install --upgrade pip --quiet
%PY% -m pip install customtkinter cryptography Pillow pyinstaller --quiet
if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    pause & exit /b 1
)
echo       Done.
echo.

set ICON_FLAG=
if exist "assets\icon.ico" (
    echo       Found custom icon: assets\icon.ico
    set ICON_FLAG=--icon "assets\icon.ico"
) else (
    echo       No custom icon found at assets\icon.ico - building with default icon.
)
echo.

echo [3/4] Building Hidec.exe with PyInstaller...
echo       This may take 2-5 minutes...
echo.

%PY% -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name "Hidec" ^
    %ICON_FLAG% ^
    --hidden-import customtkinter ^
    --hidden-import PIL._tkinter_finder ^
    --hidden-import cryptography ^
    --hidden-import auth ^
    --hidden-import database ^
    --hidden-import encryption ^
    --hidden-import pin_manager ^
    --collect-all customtkinter ^
    --add-data "auth.py;." ^
    --add-data "database.py;." ^
    --add-data "encryption.py;." ^
    --add-data "pin_manager.py;." ^
    --clean ^
    --noconfirm ^
    main.py

if errorlevel 1 (
    echo.
    echo ERROR: Build failed. See output above for details.
    echo Common fixes:
    echo   - Close any running Hidec.exe before rebuilding
    echo   - Run this script as Administrator
    echo   - Check that all .py files are in the same folder
    pause & exit /b 1
)

echo.
echo [4/4] Build complete!
echo ============================================================
echo   Output file: dist\Hidec.exe
echo.
echo   To run:   double-click dist\Hidec.exe
echo   To share: copy dist\Hidec.exe to any Windows PC
echo             (no Python installation needed on the target PC)
echo ============================================================
echo.
pause
