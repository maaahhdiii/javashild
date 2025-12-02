@echo off
REM JavaShield - AI Security Agent Runner
REM ======================================

echo.
echo  ╔═══════════════════════════════════════════════════╗
echo  ║         JavaShield - AI Security Platform         ║
echo  ║              Java 25 + Spring Boot 3.4            ║
echo  ╚═══════════════════════════════════════════════════╝
echo.

REM Set Java 25 environment
set JAVA_HOME=d:\.jdk\jdk-25
set PATH=%JAVA_HOME%\bin;%PATH%

REM Verify Java version
echo [INFO] Checking Java version...
java -version 2>&1 | findstr /C:"25.0.1" >nul
if %errorlevel% neq 0 (
    echo [ERROR] Java 25 not found! Please ensure Java 25 is installed at d:\.jdk\jdk-25
    pause
    exit /b 1
)
echo [SUCCESS] Java 25.0.1 detected
echo.

REM Check if Maven is available
where mvn >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Maven not found! Please install Maven and add it to PATH
    pause
    exit /b 1
)
echo [SUCCESS] Maven detected
echo.

REM Clean and build project
echo [INFO] Building JavaShield...
echo [INFO] Running: mvn clean package -DskipTests
echo.
call mvn clean package -DskipTests

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed! Please check the error messages above.
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Build completed successfully!
echo.

REM Check if port 8080 is already in use
netstat -ano | findstr ":8080" | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo [WARNING] Port 8080 is already in use!
    echo [INFO] Attempting to free port 8080...
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8080" ^| findstr "LISTENING"') do (
        echo [INFO] Killing process %%a...
        taskkill /F /PID %%a >nul 2>&1
    )
    timeout /t 2 /nobreak >nul
)

echo.
echo [INFO] Starting JavaShield Web Application...
echo [INFO] Server will be available at: http://localhost:8080
echo [INFO] Press Ctrl+C to stop the application
echo.
echo ════════════════════════════════════════════════════
echo.

REM Run the Spring Boot application
call mvn spring-boot:run

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Application failed to start! Check logs above.
    pause
    exit /b 1
)
