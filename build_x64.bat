@echo off
setlocal
where cmake >nul 2>nul
if errorlevel 1 (
  echo CMake introuvable.
  echo Installe Visual Studio Build Tools 2022 avec "Desktop development with C++".
  pause
  exit /b 1
)

cmake -S . -B build -A x64
if errorlevel 1 pause & exit /b 1

cmake --build build --config Release
if errorlevel 1 pause & exit /b 1

echo.
echo DLL creee dans:
echo build\Release\XINPUT9_1_0.dll
pause
