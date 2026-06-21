@echo off
echo ============================================
echo  Hidec - Windows Build Script (no icon)
echo ============================================
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.11+ from python.org
    pause
    exit /b 1
)

echo [1/3] Installing dependencies...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    pause
    exit /b 1
)

echo [2/3] Building .exe with PyInstaller...
pyinstaller ^
    --onefile ^
    --windowed ^
    --name "Hidec" ^
    --hidden-import customtkinter ^
    --hidden-import PIL._tkinter_finder ^
    --collect-all customtkinter ^
    --clean ^
    main.py

if errorlevel 1 (
    echo.
    echo ERROR: Build failed. See output above.
    pause
    exit /b 1
)

echo.
echo [3/3] Done!
echo ============================================
echo  Output: dist\Hidec.exe
echo ============================================
echo.
pause
