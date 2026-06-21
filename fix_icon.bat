@echo off
echo ============================================================
echo   FolderLock - Icon Fixer
echo ============================================================
echo.

where py >nul 2>&1
if not errorlevel 1 (
    set PY=py
    goto :found
)
where python >nul 2>&1
if not errorlevel 1 (
    set PY=python
    goto :found
)
echo ERROR: Python not found.
pause & exit /b 1

:found
echo Installing Pillow (image library)...
%PY% -m pip install --upgrade Pillow --quiet
echo.
%PY% fix_icon.py
echo.
pause
