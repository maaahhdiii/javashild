$body = @{
    code = @'
import java.sql.*;

public class VulnerableCode {
    public void getUserData(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id=" + userId;
        ResultSet rs = stmt.executeQuery(query);
    }
}
'@
    filename = 'VulnerableCode.java'
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8080/api/security/analyze/code" -Method Post -Body $body -ContentType "application/json"

Write-Host "=== API Response ===" -ForegroundColor Cyan
$response | ConvertTo-Json -Depth 10

Write-Host "`n=== Checking for fixCode field ===" -ForegroundColor Yellow
if ($response.findings -and $response.findings.Count -gt 0) {
    $firstFinding = $response.findings[0]
    Write-Host "First finding category: $($firstFinding.category)" -ForegroundColor Green
    Write-Host "All properties:" -ForegroundColor Cyan
    $firstFinding | Get-Member -MemberType NoteProperty | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Gray }
    Write-Host "`nHas fixCode field: $($null -ne $firstFinding.fixCode)" -ForegroundColor $(if ($firstFinding.fixCode) { "Green" } else { "Red" })
    Write-Host "fixCode value: $($firstFinding.fixCode)" -ForegroundColor Yellow
    if ($firstFinding.fixCode) {
        Write-Host "Fix code preview (first 100 chars): $($firstFinding.fixCode.Substring(0, [Math]::Min(100, $firstFinding.fixCode.Length)))" -ForegroundColor Magenta
    }
}
