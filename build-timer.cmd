@echo off
REM Build both timer backends with the Host NDK (no JDK needed).
REM Usage: build-timer.cmd  (run inside timer-native\)
setlocal
set NDK=H:\Android\Sdk\ndk\29.0.14206865\toolchains\llvm\prebuilt\windows-x86_64\bin
if not exist "%NDK%\aarch64-linux-android35-clang.cmd" (
  echo NDK clang not found at %NDK%
  exit /b 1
)
copy /y target-6.1.145.h target.h >nul
call "%NDK%\aarch64-linux-android35-clang.cmd" -O2 -std=gnu11 -static -fno-stack-protector -fno-pic -I. -ffunction-sections -fdata-sections timer.c -o timer-6.1.145 -Wl,--gc-sections -Wl,-s -Wl,--build-id=none -Wl,-z,norelro -pthread
if errorlevel 1 exit /b 1
copy /y target-6.1.124.h target.h >nul
call "%NDK%\aarch64-linux-android35-clang.cmd" -O2 -std=gnu11 -static -fno-stack-protector -fno-pic -I. -ffunction-sections -fdata-sections timer.c -o timer-6.1.124 -Wl,--gc-sections -Wl,-s -Wl,--build-id=none -Wl,-z,norelro -pthread
if errorlevel 1 exit /b 1
copy /y target-6.1.57.h target.h >nul
call "%NDK%\aarch64-linux-android35-clang.cmd" -O2 -std=gnu11 -static -fno-stack-protector -fno-pic -I. -ffunction-sections -fdata-sections timer.c -o timer-6.1.57 -Wl,--gc-sections -Wl,-s -Wl,--build-id=none -Wl,-z,norelro -pthread
if errorlevel 1 exit /b 1
del target.h
dir timer-6.1.145 timer-6.1.124 timer-6.1.57
echo BUILD_OK
