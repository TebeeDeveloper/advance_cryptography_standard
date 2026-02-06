@echo off
setlocal enabledelayedexpansion
title AEMS Installer - Tebee

:: 1. Kiểm tra Colorama
python -c "import colorama" 2>nul
if %errorlevel% neq 0 (
    echo [!] Dang cai dat colorama...
    pip install colorama
)

:: 3. Chạy Terminal
cls
python terminal.py
pause