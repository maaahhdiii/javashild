@echo off
REM JavaShield - Quick Start Script
REM ================================

echo.
echo  ╔═══════════════════════════════════════════════════╗
echo  ║         JavaShield - Quick Start                  ║
echo  ╚═══════════════════════════════════════════════════╝
echo.
echo  Choose an option:
echo.
echo  [1] Run JavaShield (build + start)
echo  [2] Build only (no run)
echo  [3] Run without building (if already built)
echo  [4] Clean build + run
echo  [5] Open in browser only
echo  [Q] Quit
echo.
set /p choice="Enter your choice: "

if /i "%choice%"=="1" goto runfull
if /i "%choice%"=="2" goto buildonly
if /i "%choice%"=="3" goto runonly
if /i "%choice%"=="4" goto cleanbuild
if /i "%choice%"=="5" goto openbrowser
if /i "%choice%"=="q" goto end
goto menu

:runfull
echo.
echo [INFO] Building and running JavaShield...
call run.bat
goto end

:buildonly
echo.
echo [INFO] Building JavaShield...
set JAVA_HOME=d:\.jdk\jdk-25
set PATH=%JAVA_HOME%\bin;%PATH%
call mvn clean package -DskipTests
echo.
echo [SUCCESS] Build complete! Use option 3 to run.
pause
goto end

:runonly
echo.
echo [INFO] Starting JavaShield (no build)...
set JAVA_HOME=d:\.jdk\jdk-25
set PATH=%JAVA_HOME%\bin;%PATH%
call mvn spring-boot:run
goto end

:cleanbuild
echo.
echo [INFO] Performing clean build...
set JAVA_HOME=d:\.jdk\jdk-25
set PATH=%JAVA_HOME%\bin;%PATH%
call mvn clean
call mvn clean package -DskipTests
call mvn spring-boot:run
goto end

:openbrowser
echo.
echo [INFO] Opening JavaShield in browser...
start http://localhost:8080
timeout /t 2 /nobreak >nul
echo [INFO] If the application isn't running, start it first (option 1)
pause
goto end

:end
exit /b 0
