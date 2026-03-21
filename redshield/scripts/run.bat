@echo off
REM run.bat — Lance REDSHIELD en mode développement
REM Usage : scripts\run.bat

cd /d "%~dp0\.."
echo [REDSHIELD] Lancement en mode developpement...
python redshield.py
