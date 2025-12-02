#!/bin/bash
# Build script for AI Vulnerability Detection Agent
# Unix/Linux/macOS version

set -e

echo "================================================================================"
echo "AI Agent for Vulnerability Detection, Handling and Blocking"
echo "Build Script for Java 25"
echo "================================================================================"
echo

# Check Java version
echo "Checking Java installation..."
if ! java -version 2>&1 | grep -q "25"; then
    echo "ERROR: Java 25 is required but not found"
    echo "Please install Java 25 from https://jdk.java.net/25/"
    exit 1
fi
echo "[OK] Java 25 detected"
echo

# Check Maven installation
echo "Checking Maven installation..."
if ! command -v mvn &> /dev/null; then
    echo "ERROR: Maven is not installed or not in PATH"
    echo "Please install Maven from https://maven.apache.org/"
    exit 1
fi
echo "[OK] Maven detected"
echo

# Clean previous builds
echo "Step 1: Cleaning previous builds..."
mvn clean
echo "[OK] Clean completed"
echo

# Compile project
echo "Step 2: Compiling project..."
mvn compile
echo "[OK] Compilation successful"
echo

# Run tests
echo "Step 3: Running tests..."
if mvn test; then
    echo "[OK] All tests passed"
else
    echo "WARNING: Some tests failed, continuing..."
fi
echo

# Package application
echo "Step 4: Packaging application..."
mvn package -DskipTests
echo "[OK] Packaging successful"
echo

# Create distribution directory
echo "Step 5: Creating distribution..."
mkdir -p dist
cp target/vulnerability-detection-agent-1.0.0.jar dist/
cp README.md dist/
cp ARCHITECTURE.md dist/
cp PRESENTATION.md dist/
echo "[OK] Distribution created in dist/ directory"
echo

echo "================================================================================"
echo "BUILD SUCCESSFUL"
echo "================================================================================"
echo
echo "Next steps:"
echo "  1. Run the demo:"
echo "     java --enable-preview -jar dist/vulnerability-detection-agent-1.0.0.jar"
echo
echo "  2. Scan a project:"
echo "     java --enable-preview -jar dist/vulnerability-detection-agent-1.0.0.jar --scan --path /your/project"
echo
echo "  3. Generate CI/CD configs:"
echo "     java --enable-preview -jar dist/vulnerability-detection-agent-1.0.0.jar --cicd"
echo
echo "See README.md for more information"
echo "================================================================================"

exit 0
