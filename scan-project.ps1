# JavaShield Security Scanner Script
# Scans a project folder and running application for security vulnerabilities

param(
    [string]$SourcePath = "D:\test target\vulnerable-web-application-target\src\main\java",
    [string]$TargetUrl = "http://localhost:8081",
    [string]$JavaShieldUrl = "http://localhost:8080",
    [switch]$AutoFix = $false,
    [switch]$ScheduleHourly = $false
)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " JavaShield Security Scanner" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if JavaShield is running
try {
    $status = Invoke-RestMethod -Uri "$JavaShieldUrl/api/security/status" -TimeoutSec 5
    Write-Host "[+] JavaShield Status: $($status.status)" -ForegroundColor Green
} catch {
    Write-Host "[-] JavaShield is not running at $JavaShieldUrl" -ForegroundColor Red
    Write-Host "    Please start JavaShield first: cd D:\jabaproj; .\run.bat" -ForegroundColor Yellow
    exit 1
}

# Check if target app is running
if ($TargetUrl) {
    try {
        $null = Invoke-WebRequest -Uri $TargetUrl -TimeoutSec 5 -UseBasicParsing
        Write-Host "[+] Target Application: Online at $TargetUrl" -ForegroundColor Green
    } catch {
        Write-Host "[!] Target Application: Not responding at $TargetUrl" -ForegroundColor Yellow
        Write-Host "    Dynamic scanning will be skipped" -ForegroundColor Yellow
        $TargetUrl = $null
    }
}

Write-Host ""
Write-Host "Source Path: $SourcePath" -ForegroundColor White
Write-Host "Target URL: $TargetUrl" -ForegroundColor White
Write-Host "Auto-Fix: $AutoFix" -ForegroundColor White
Write-Host ""

# Count files
$javaFiles = Get-ChildItem $SourcePath -Recurse -Filter "*.java" -ErrorAction SilentlyContinue
Write-Host "[*] Found $($javaFiles.Count) Java files to scan" -ForegroundColor White
Write-Host ""

# Scan each file
$allFindings = @()
$fileCount = 0

foreach ($file in $javaFiles) {
    $fileCount++
    $relativePath = $file.FullName.Replace($SourcePath, "").TrimStart("\")
    Write-Host "[$fileCount/$($javaFiles.Count)] Scanning: $relativePath" -ForegroundColor Gray
    
    try {
        $content = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)
        
        # Escape the content properly for JSON
        $escapedContent = $content -replace '\\', '\\\\' -replace '"', '\"' -replace "`r`n", '\n' -replace "`n", '\n' -replace "`r", '\n' -replace "`t", '\t'
        
        $jsonBody = "{`"code`":`"$escapedContent`",`"filename`":`"$($file.Name)`",`"language`":`"java`"}"
        
        $result = Invoke-RestMethod -Uri "$JavaShieldUrl/api/security/analyze/code" `
            -Method Post -Body $jsonBody -ContentType "application/json; charset=utf-8" -TimeoutSec 60
        
        if ($result.totalFindings -gt 0) {
            Write-Host "    Found $($result.totalFindings) vulnerabilities" -ForegroundColor Yellow
            foreach ($finding in $result.findings) {
                $finding | Add-Member -NotePropertyName "file" -NotePropertyValue $relativePath -Force
                $allFindings += $finding
            }
        }
    } catch {
        Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Dynamic scan if target URL provided
if ($TargetUrl) {
    Write-Host ""
    Write-Host "[*] Running dynamic scan on $TargetUrl..." -ForegroundColor White
    
    try {
        $dynamicBody = @{
            targetUrl = $TargetUrl
            autoFix = $AutoFix
        } | ConvertTo-Json
        
        $dynamicResult = Invoke-RestMethod -Uri "$JavaShieldUrl/api/security/scan/full" `
            -Method Post -Body $dynamicBody -ContentType "application/json" -TimeoutSec 120
        
        if ($dynamicResult.dynamicFindings -gt 0) {
            Write-Host "    Found $($dynamicResult.dynamicFindings) dynamic vulnerabilities" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    Dynamic scan error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Summary
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " SCAN SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Vulnerabilities: $($allFindings.Count)" -ForegroundColor White

$critical = ($allFindings | Where-Object { $_.severity -eq "CRITICAL" }).Count
$high = ($allFindings | Where-Object { $_.severity -eq "HIGH" }).Count
$medium = ($allFindings | Where-Object { $_.severity -eq "MEDIUM" }).Count
$low = ($allFindings | Where-Object { $_.severity -eq "LOW" }).Count

if ($critical -gt 0) { Write-Host "  CRITICAL: $critical" -ForegroundColor Red }
if ($high -gt 0) { Write-Host "  HIGH: $high" -ForegroundColor DarkYellow }
if ($medium -gt 0) { Write-Host "  MEDIUM: $medium" -ForegroundColor Yellow }
if ($low -gt 0) { Write-Host "  LOW: $low" -ForegroundColor Green }

# List critical and high findings
Write-Host ""
Write-Host "Critical & High Severity Findings:" -ForegroundColor Red
$allFindings | Where-Object { $_.severity -in @("CRITICAL", "HIGH") } | ForEach-Object {
    Write-Host "  [$($_.severity)] $($_.category)" -ForegroundColor $(if ($_.severity -eq "CRITICAL") { "Red" } else { "DarkYellow" })
    Write-Host "    File: $($_.file)" -ForegroundColor Gray
    if ($_.description) {
        $desc = $_.description.Substring(0, [Math]::Min(100, $_.description.Length))
        Write-Host "    $desc..." -ForegroundColor Gray
    }
    Write-Host ""
}

# Export report
$reportFile = "security-report-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').json"
$report = @{
    scanDate = (Get-Date).ToString("o")
    sourcePath = $SourcePath
    targetUrl = $TargetUrl
    filesScanned = $javaFiles.Count
    totalFindings = $allFindings.Count
    summary = @{
        critical = $critical
        high = $high
        medium = $medium
        low = $low
    }
    findings = $allFindings
}
$report | ConvertTo-Json -Depth 10 | Out-File $reportFile -Encoding UTF8
Write-Host ""
Write-Host "Report saved to: $reportFile" -ForegroundColor Green

# Schedule hourly scans
if ($ScheduleHourly) {
    Write-Host ""
    Write-Host "[*] Scheduling hourly scans..." -ForegroundColor White
    
    $projectBody = @{
        projectName = "TechStore Security Scan"
        sourcePath = $SourcePath
        targetUrl = $TargetUrl
    } | ConvertTo-Json
    
    $project = Invoke-RestMethod -Uri "$JavaShieldUrl/api/security/projects/register" `
        -Method Post -Body $projectBody -ContentType "application/json"
    
    if ($project.success) {
        $scheduleBody = @{
            intervalMs = 3600000
            intervalName = "Hourly"
            autoFix = $AutoFix
        } | ConvertTo-Json
        
        $schedule = Invoke-RestMethod -Uri "$JavaShieldUrl/api/security/projects/$($project.projectId)/schedule" `
            -Method Post -Body $scheduleBody -ContentType "application/json"
        
        Write-Host "[+] Hourly scans scheduled. Project ID: $($project.projectId)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Scan complete!" -ForegroundColor Green
