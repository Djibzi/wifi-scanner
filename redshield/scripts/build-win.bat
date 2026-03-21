@echo off
REM build-win.bat — Compile REDSHIELD en .exe pour Windows
REM Usage : scripts\build-win.bat

echo [REDSHIELD] Build Windows...
echo.

cd /d "%~dp0\.."

REM Installer les dépendances
echo [1/3] Installation des dependances...
pip install -r backend\requirements.txt
if %errorlevel% neq 0 (
    echo ERREUR: Installation des dependances echouee
    exit /b 1
)

REM Compiler avec PyInstaller
echo [2/3] Compilation avec PyInstaller...
pyinstaller --onefile --name redshield ^
    --add-data "frontend;frontend" ^
    --add-data "..\core;core" ^
    --add-data "..\modules;modules" ^
    --add-data "..\vuln_db;vuln_db" ^
    --add-data "..\reports;reports" ^
    --add-data "backend\core;backend_core" ^
    --add-data "backend\api;api" ^
    --hidden-import=eventlet ^
    --hidden-import=flask_socketio ^
    --hidden-import=flask_cors ^
    --hidden-import=webview ^
    --hidden-import=engineio.async_drivers.threading ^
    --icon=frontend\assets\app-icon.ico ^
    --noconsole ^
    redshield.py

if %errorlevel% neq 0 (
    echo ERREUR: Compilation echouee
    exit /b 1
)

echo [3/3] Build termine !
echo.
echo Executable : dist\redshield.exe
echo.
pause
