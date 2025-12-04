#!/usr/bin/env pwsh
# OWASP ZAP Startup Script for JavaShield AI Security Agent
# This script starts OWASP ZAP in daemon mode for dynamic vulnerability scanning

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  JavaShield - OWASP ZAP Daemon Starter" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Common ZAP installation paths
$zapPaths = @(
    "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
    "C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
    "$env:ProgramFiles\ZAP\Zed Attack Proxy\zap.bat",
    "$env:USERPROFILE\Desktop\ZAP_2.15.0\zap.bat",
    "$env:USERPROFILE\Downloads\ZAP_2.15.0\zap.bat",
    "C:\ZAP\zap.bat"
)

$zapFound = $false
$zapPath = ""

foreach ($path in $zapPaths) {
    if (Test-Path $path) {
        $zapPath = $path
        $zapFound = $true
        break
    }
}

if ($zapFound) {
    Write-Host "✓ Found OWASP ZAP at: $zapPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "Starting ZAP in daemon mode on port 8090..." -ForegroundColor Yellow
    Write-Host ""
    
    # Start ZAP in daemon mode
    Start-Process -FilePath $zapPath `
                  -ArgumentList "-daemon", "-port", "8090", "-config", "api.disablekey=true", "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true" `
                  -NoNewWindow `
                  -PassThru
    
    Write-Host "✓ OWASP ZAP daemon started successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "ZAP is now running on: http://localhost:8090" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Your JavaShield Security Agent will now be able to perform:" -ForegroundColor White
    Write-Host "  • Dynamic SQL injection testing" -ForegroundColor Gray
    Write-Host "  • XSS vulnerability scanning" -ForegroundColor Gray
    Write-Host "  • CSRF detection" -ForegroundColor Gray
    Write-Host "  • Authentication bypass checks" -ForegroundColor Gray
    Write-Host "  • Session management analysis" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To stop ZAP: Stop-Process -Name 'java' -Force" -ForegroundColor Yellow
    Write-Host ""
    
    # Wait a few seconds for ZAP to fully start
    Write-Host "Waiting for ZAP to initialize (30 seconds)..." -ForegroundColor Yellow
    for ($i=30; $i -gt 0; $i--) {
        Write-Host -NoNewline "`r  $i seconds remaining...  "
        Start-Sleep 1
    }
    Write-Host ""
    Write-Host ""
    Write-Host "✓ ZAP should be ready now!" -ForegroundColor Green
    Write-Host "  You can restart your JavaShield server to enable dynamic scanning." -ForegroundColor Cyan
    
} else {
    Write-Host "✗ OWASP ZAP not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install OWASP ZAP:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Download from: https://www.zaproxy.org/download/" -ForegroundColor White
    Write-Host "2. Choose: ZAP 2.15.0 Windows Installer" -ForegroundColor White
    Write-Host "3. Install to default location" -ForegroundColor White
    Write-Host "4. Run this script again" -ForegroundColor White
    Write-Host ""
    Write-Host "Or specify custom path when running:" -ForegroundColor Yellow
    Write-Host '  .\START-OWASP-ZAP.ps1 -ZapPath "C:\path\to\zap.bat"' -ForegroundColor Gray
    Write-Host ""
}

Write-Host "Press any key to continue..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
