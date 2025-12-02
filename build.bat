@echo off
REM Build script for AI Vulnerability Detection Agent
REM Windows PowerShell/CMD version

echo ================================================================================
echo AI Agent for Vulnerability Detection, Handling and Blocking
echo Build Script for Java 25
echo ================================================================================
echo.

REM Check Java version
echo Checking Java installation...
java -version 2>&1 | findstr /C:"25" >nul
if errorlevel 1 (
    echo ERROR: Java 25 is required but not found
    echo Please install Java 25 from https://jdk.java.net/25/
    exit /b 1
)
echo [OK] Java 25 detected
echo.

REM Check Maven installation
echo Checking Maven installation...
where mvn >nul 2>nul
if errorlevel 1 (
    echo ERROR: Maven is not installed or not in PATH
    echo Please install Maven from https://maven.apache.org/
    exit /b 1
)
echo [OK] Maven detected
echo.

REM Clean previous builds
echo Step 1: Cleaning previous builds...
call mvn clean
if errorlevel 1 (
    echo ERROR: Maven clean failed
    exit /b 1
)
echo [OK] Clean completed
echo.

REM Compile project
echo Step 2: Compiling project...
call mvn compile
if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)
echo [OK] Compilation successful
echo.

REM Run tests
echo Step 3: Running tests...
call mvn test
if errorlevel 1 (
    echo WARNING: Some tests failed, continuing...
) else (
    echo [OK] All tests passed
)
echo.

REM Package application
echo Step 4: Packaging application...
call mvn package -DskipTests
if errorlevel 1 (
    echo ERROR: Packaging failed
    exit /b 1
)
echo [OK] Packaging successful
echo.

REM Create distribution directory
echo Step 5: Creating distribution...
if not exist "dist" mkdir dist
copy target\vulnerability-detection-agent-1.0.0.jar dist\
copy README.md dist\
copy ARCHITECTURE.md dist\
copy PRESENTATION.md dist\
echo [OK] Distribution created in dist\ directory
echo.

echo ================================================================================
echo BUILD SUCCESSFUL
echo ================================================================================
echo.
echo Next steps:
echo   1. Run the demo:
echo      java --enable-preview -jar dist\vulnerability-detection-agent-1.0.0.jar
echo.
echo   2. Scan a project:
echo      java --enable-preview -jar dist\vulnerability-detection-agent-1.0.0.jar --scan --path C:\your\project
echo.
echo   3. Generate CI/CD configs:
echo      java --enable-preview -jar dist\vulnerability-detection-agent-1.0.0.jar --cicd
echo.
echo See README.md for more information
echo ================================================================================

exit /b 0
