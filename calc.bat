@echo off
set "SCRIPT_PATH=%~dp0win2doom.ps1"

if not exist "%SCRIPT_PATH%" (
    echo Ошибка: Файл win2doom.ps1 не найден в текущей папке!
    pause
    exit /b 1
)

powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -noninteractive -File ""%SCRIPT_PATH%"" -Verb RunAs



pause