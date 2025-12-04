# JavaShield AI Security Agent - REST API Documentation

**Base URL:** `http://localhost:8080/api/security`

---

## 🔍 Code Analysis Endpoints

### 1. **Analyze Code File**
Upload a source code file for comprehensive security analysis with ML-enhanced vulnerability detection.

**Endpoint:** `POST /analyze/file`

**Content-Type:** `multipart/form-data`

**Parameters:**
- `file` (required): Source code file to analyze

**Example Request (cURL):**
```bash
curl -X POST http://localhost:8080/api/security/analyze/file \
  -F "file=@/path/to/YourClass.java"
```

**Example Request (PowerShell):**
```powershell
$file = Get-Item "C:\code\YourClass.java"
$form = @{
    file = $file
}
Invoke-RestMethod -Uri "http://localhost:8080/api/security/analyze/file" `
    -Method Post -Form $form
```

**Response:**
```json
{
  "status": "success",
  "analysisId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "findings": [
    {
      "findingId": "f1234567-89ab-cdef-0123-456789abcdef",
      "detectedAt": "2025-12-03T20:30:00Z",
      "severity": "CRITICAL",
      "category": "SQL_INJECTION",
      "description": "[ML: VULNERABLE @98%] SQL injection vulnerability detected",
      "location": "UserService.java:45",
      "cveId": null,
      "confidenceScore": 0.95,
      "recommendations": [
        "Use prepared statements with parameterized queries",
        "Validate and sanitize all user inputs"
      ],
      "autoRemediationPossible": true
    }
  ],
  "summary": {
    "totalFindings": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0,
    "mlEnhanced": true,
    "averageConfidence": 0.92
  },
  "timestamp": "2025-12-03T20:30:00Z"
}
```

---

### 2. **Analyze Code Snippet**
Analyze raw code without uploading a file.

**Endpoint:** `POST /analyze/code`

**Content-Type:** `application/json`

**Request Body:**
```json
{
  "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;",
  "language": "java",
  "filename": "snippet.java"
}
```

**Example Request (cURL):**
```bash
curl -X POST http://localhost:8080/api/security/analyze/code \
  -H "Content-Type: application/json" \
  -d '{
    "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;",
    "language": "java",
    "filename": "UserService.java"
  }'
```

**Example Request (PowerShell):**
```powershell
$body = @{
    code = 'String query = "SELECT * FROM users WHERE id = " + userId;'
    language = "java"
    filename = "UserService.java"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8080/api/security/analyze/code" `
    -Method Post -Body $body -ContentType "application/json"
```

---

### 3. **Analyze Project Directory**
Scan an entire project directory for vulnerabilities.

**Endpoint:** `POST /analyze/project`

**Content-Type:** `application/json`

**Request Body:**
```json
{
  "projectPath": "/path/to/project",
  "excludePatterns": ["**/test/**", "**/target/**"],
  "deepScan": true
}
```

**Example Request (cURL):**
```bash
curl -X POST http://localhost:8080/api/security/analyze/project \
  -H "Content-Type: application/json" \
  -d '{
    "projectPath": "/home/user/myproject",
    "excludePatterns": ["**/test/**", "**/target/**"],
    "deepScan": true
  }'
```

---

## 🤖 Machine Learning Endpoints

### 4. **Submit Feedback for Continuous Learning**
Provide labeled feedback to improve ML model accuracy.

**Endpoint:** `POST /feedback`

**Content-Type:** `application/json`

**Request Body:**
```json
{
  "findingId": "f1234567-89ab-cdef-0123-456789abcdef",
  "correctLabel": "VULNERABLE",
  "confidence": 0.95,
  "finding": {
    "title": "SQL Injection",
    "description": "Potential SQL injection",
    "severity": "CRITICAL",
    "confidence": 0.89,
    "category": "SQL_INJECTION",
    "location": "UserService.java:45",
    "codeSnippet": "String query = ...",
    "recommendation": "Use PreparedStatement"
  }
}
```

**Labels:** `VULNERABLE`, `SAFE`, `SUSPICIOUS`

**Example Request (cURL):**
```bash
curl -X POST http://localhost:8080/api/security/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "findingId": "f1234567",
    "correctLabel": "VULNERABLE",
    "confidence": 0.95,
    "finding": {
      "title": "SQL Injection",
      "description": "SQL injection detected",
      "severity": "CRITICAL",
      "confidence": 0.89,
      "category": "SQL_INJECTION",
      "location": "UserService.java:45",
      "codeSnippet": "String query = ...",
      "recommendation": "Use PreparedStatement"
    }
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "Feedback recorded for continuous learning",
  "feedbackBufferSize": 12
}
```

---

### 5. **Trigger Manual ML Model Retraining**
Manually trigger model retraining with collected feedback.

**Endpoint:** `POST /retrain`

**Example Request (cURL):**
```bash
curl -X POST http://localhost:8080/api/security/retrain
```

**Example Request (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/security/retrain" -Method Post
```

**Response:**
```json
{
  "success": true,
  "message": "Retraining started in background",
  "currentStats": {
    "totalAnalyzed": 150,
    "threatsBlocked": 12,
    "autoFixesApplied": 8,
    "retrainingCount": 3,
    "feedbackSamples": 52,
    "lastRetrainTime": "2025-12-03T18:30:00Z"
  }
}
```

---

## 🛡️ Threat Response Endpoints

### 6. **Get Auto-Fix for Vulnerability**
Generate automatic fix for detected vulnerability.

**Endpoint:** `POST /autofix`

**Content-Type:** `application/json`

**Request Body:**
```json
{
  "findingId": "f1234567-89ab-cdef-0123-456789abcdef",
  "sourceCode": "String query = \"SELECT * FROM users WHERE id = \" + userId;",
  "vulnerabilityType": "SQL_INJECTION"
}
```

**Example Request (cURL):**
```bash
curl -X POST http://localhost:8080/api/security/autofix \
  -H "Content-Type: application/json" \
  -d '{
    "findingId": "f1234567",
    "sourceCode": "String query = \"SELECT * FROM users WHERE id = \" + userId;",
    "vulnerabilityType": "SQL_INJECTION"
  }'
```

**Response:**
```json
{
  "success": true,
  "fixedCode": "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nstmt.setString(1, userId);",
  "explanation": "Replaced string concatenation with parameterized query using PreparedStatement",
  "confidence": 0.95
}
```

---

## 📊 Monitoring Endpoints

### 7. **Get System Status**
Check agent health and operational status.

**Endpoint:** `GET /status`

**Example Request (cURL):**
```bash
curl http://localhost:8080/api/security/status
```

**Example Request (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/security/status"
```

**Response:**
```json
{
  "status": "OPERATIONAL",
  "totalAgents": 1,
  "activeAgents": 1,
  "agents": [
    {
      "agentId": "a093cf67-1929-4f83-99ed-84f7728440c5",
      "type": "UNIFIED_ML_AGENT",
      "status": "RUNNING",
      "health": "Healthy - 150 scans, 12 threats blocked"
    }
  ]
}
```

---

### 8. **Get Health Check**
Simple health check endpoint.

**Endpoint:** `GET /health`

**Example Request (cURL):**
```bash
curl http://localhost:8080/api/security/health
```

**Response:**
```json
{
  "status": "UP",
  "agent": "RUNNING",
  "mlModel": "TRAINED",
  "timestamp": "2025-12-03T20:30:00Z"
}
```

---

### 9. **Get Statistics**
Get detailed system statistics including ML metrics.

**Endpoint:** `GET /statistics`

**Example Request (cURL):**
```bash
curl http://localhost:8080/api/security/statistics
```

**Example Request (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/security/statistics"
```

**Response:**
```json
{
  "totalScans": 150,
  "totalFindings": 342,
  "threatsBlocked": 12,
  "agentStats": {
    "totalAnalyzed": 150,
    "threatsBlocked": 12,
    "autoFixesApplied": 8,
    "retrainingCount": 3,
    "feedbackSamples": 52,
    "lastRetrainTime": "2025-12-03T18:30:00Z",
    "queueSize": 0,
    "cachedFindings": 45
  },
  "mlMetrics": {
    "modelAccuracy": 0.9464,
    "vulnerableAccuracy": 1.0,
    "safeAccuracy": 1.0,
    "suspiciousAccuracy": 0.6538,
    "trainingExamples": 840,
    "lastTrainedAt": "2025-12-03T20:30:00Z"
  }
}
```

---

### 10. **Get Analysis History**
Retrieve past analysis results.

**Endpoint:** `GET /history`

**Query Parameters:**
- `limit` (optional): Number of results (default: 50)
- `severity` (optional): Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)

**Example Request (cURL):**
```bash
curl "http://localhost:8080/api/security/history?limit=10&severity=CRITICAL"
```

**Example Request (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/security/history?limit=10&severity=CRITICAL"
```

---

## 🔗 Integration Examples

### Python Integration
```python
import requests

# Analyze code file
with open('MyClass.java', 'rb') as f:
    files = {'file': f}
    response = requests.post(
        'http://localhost:8080/api/security/analyze/file',
        files=files
    )
    result = response.json()
    print(f"Found {result['summary']['totalFindings']} vulnerabilities")

# Submit feedback
feedback = {
    'findingId': 'f1234567',
    'correctLabel': 'VULNERABLE',
    'confidence': 0.95,
    'finding': {
        'title': 'SQL Injection',
        'severity': 'CRITICAL',
        'category': 'SQL_INJECTION'
        # ... other fields
    }
}
response = requests.post(
    'http://localhost:8080/api/security/feedback',
    json=feedback
)
```

### Node.js Integration
```javascript
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');

// Analyze file
const form = new FormData();
form.append('file', fs.createReadStream('MyClass.java'));

axios.post('http://localhost:8080/api/security/analyze/file', form, {
    headers: form.getHeaders()
})
.then(response => {
    console.log(`Findings: ${response.data.summary.totalFindings}`);
})
.catch(error => console.error(error));

// Get statistics
axios.get('http://localhost:8080/api/security/statistics')
    .then(response => console.log(response.data));
```

### Java Integration
```java
import java.net.http.*;
import java.net.URI;

HttpClient client = HttpClient.newHttpClient();

// Analyze code snippet
String json = """
{
    "code": "String query = \\"SELECT * FROM users WHERE id = \\" + userId;",
    "language": "java",
    "filename": "UserService.java"
}
""";

HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("http://localhost:8080/api/security/analyze/code"))
    .header("Content-Type", "application/json")
    .POST(HttpRequest.BodyPublishers.ofString(json))
    .build();

HttpResponse<String> response = client.send(request, 
    HttpResponse.BodyHandlers.ofString());
System.out.println(response.body());
```

### C# Integration
```csharp
using System.Net.Http;
using System.Text;
using System.Text.Json;

var client = new HttpClient();
var baseUrl = "http://localhost:8080/api/security";

// Analyze code
var codeData = new {
    code = "String query = \"SELECT * FROM users WHERE id = \" + userId;",
    language = "java",
    filename = "UserService.java"
};

var content = new StringContent(
    JsonSerializer.Serialize(codeData),
    Encoding.UTF8,
    "application/json"
);

var response = await client.PostAsync($"{baseUrl}/analyze/code", content);
var result = await response.Content.ReadAsStringAsync();
Console.WriteLine(result);
```

---

## 📋 Response Codes

| Code | Description |
|------|-------------|
| 200  | Success |
| 400  | Bad Request - Invalid input |
| 500  | Internal Server Error |
| 503  | Service Unavailable - Agent not ready |

---

## 🎯 Best Practices

1. **Rate Limiting**: Implement rate limiting on your client side
2. **Feedback Loop**: Submit feedback for false positives/negatives to improve ML accuracy
3. **Batch Processing**: For large projects, use project analysis endpoint
4. **Error Handling**: Always check response status and handle errors gracefully
5. **Security**: Use HTTPS in production, implement authentication
6. **Monitoring**: Regularly check `/status` endpoint for agent health

---

## 🔄 Continuous Learning Workflow

1. **Analyze Code** → Get ML-enhanced findings
2. **Review Results** → Verify accuracy
3. **Submit Feedback** → Correct mislabeled findings via `/feedback`
4. **Automatic Retrain** → Model retrains every 24 hours or 50 feedback samples
5. **Manual Retrain** → Trigger immediate retraining via `/retrain`
6. **Improved Accuracy** → Next analysis uses updated model

---

## 📞 Support

For issues or feature requests, visit: https://github.com/maaahhdiii/javashild
