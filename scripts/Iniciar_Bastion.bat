@echo off
setlocal
set "ROOT=%~dp0.."

if not exist "%ROOT%\Bastion.exe" (
  echo Compilando Bastion.exe...
  powershell -ExecutionPolicy Bypass -File "%ROOT%\scripts\build-desktop.ps1" -RebuildWeb
  if errorlevel 1 (
    echo Error al compilar Bastion.exe.
    pause
    exit /b 1
  )
)

start "" "%ROOT%\Bastion.exe"
endlocal
