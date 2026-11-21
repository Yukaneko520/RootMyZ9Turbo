@echo off
REM Build the timer backends with the Host NDK (no JDK needed) and publish
REM them into the app assets, so the APK can never ship a stale binary.
REM Usage: build-timer.cmd  (run inside timer-native\)
setlocal
set NDK=H:\Android\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin
if not exist "%NDK%\aarch64-linux-android35-clang.cmd" (
  echo NDK clang not found at %NDK%
  exit /b 1
)
set ASSETS=..\TimerZ9Turbo-src\app\src\main\assets
call :build 6.1.145 timer
if errorlevel 1 exit /b 1
call :build 6.1.124 timer-6.1.124
if errorlevel 1 exit /b 1
call :build 6.1.57 timer-6.1.57
if errorlevel 1 exit /b 1
del target.h 2>nul
dir timer-6.1.145 timer-6.1.124 timer-6.1.57
echo BUILD_OK
exit /b 0

:build
REM %1 = target header suffix, %2 = output name (and app asset name)
copy /y target-%1.h target.h >nul
call "%NDK%\aarch64-linux-android35-clang.cmd" -O2 -std=gnu11 -static -fno-stack-protector -fno-pic -I. -ffunction-sections -fdata-sections timer.c -o timer-%1 -Wl,--gc-sections -Wl,-s -Wl,--build-id=none -Wl,-z,norelro -pthread
if errorlevel 1 exit /b 1
if exist "%ASSETS%\" (
  copy /y timer-%1 "%ASSETS%\%2" >nul
  if errorlevel 1 (
    echo cannot publish timer-%1 to %ASSETS%\%2
    exit /b 1
  )
  echo published timer-%1 -^> %ASSETS%\%2
) else (
  echo warning: app assets not found at %ASSETS%, binary not published
)
exit /b 0
