# JavaShield - AI Security Platform
## Java 25 + Spring Boot 3.4 - Advanced Security Automation System

[![Java](https://img.shields.io/badge/Java-25-orange.svg)](https://jdk.java.net/25/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.4-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-javashild-blue.svg)](https://github.com/maaahhdiii/javashild)

## 🎯 Overview

JavaShield is an intelligent AI-driven security platform that automatically detects, analyzes, handles, and **auto-fixes** security vulnerabilities in real-time. Built with Java 25 and Spring Boot 3.4, leveraging virtual threads, structured concurrency, and machine learning for autonomous security management.

**🌐 Web Interface Available** - Professional web-based UI with one-click auto-fix for 9 vulnerability types!

**🔧 Auto-Remediation Feature** - Intelligent code transformation with interactive diff viewer and security comments!

## ✨ Key Features

### 🔍 Multi-Layer Detection
- **Static Analysis**: AST parsing with 9 vulnerability types
- **Dynamic Analysis**: Runtime behavior monitoring
- **ML Classification**: Tribuo-based risk assessment
- **Auto-Remediation**: Intelligent code fixing for detected vulnerabilities

### 🤖 Autonomous Agents
- Virtual thread-based architecture using Java 25
- Structured concurrency for parallel analysis
- Self-managing agent lifecycle
- Real-time threat detection and response

### 🛡️ Automated Security
- **Auto-Fix System**: Automatically generates fixes for 9 vulnerability types
- Intelligent threat blocking
- Automated alerting system
- Interactive diff viewer for code changes

### 🌐 Professional Web Interface
- Modern, responsive UI with dark theme
- Real-time agent monitoring dashboard
- **3 Analysis Modes**: Code input, file upload, network scanning
- **Auto-Fix Feature**: One-click vulnerability remediation
- Live vulnerability detection with confidence scores
- Copy-to-clipboard functionality

### 🔄 CI/CD Integration
- Jenkins pipeline support
- GitHub Actions workflows
- GitLab CI/CD configurations
- SARIF format support

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      Code/Application                        │
└────────────────────┬─────────────────────────────────────────┘
                     │
        ┌────────────▼───────────────┐
        │   Agent Orchestrator       │
        │  (Virtual Threads + SC)    │
        └────────┬───────────────────┘
                 │
    ┌────────────┼────────────┬──────────────┐
    │            │            │              │
┌───▼───┐  ┌───▼───┐   ┌────▼────┐  ┌─────▼─────┐
│Static │  │Dynamic│   │   ML    │  │ Response  │
│ Agent │  │ Agent │   │  Agent  │  │  Agent    │
└───┬───┘  └───┬───┘   └────┬────┘  └─────┬─────┘
    │          │            │              │
    │          │            │              │
┌───▼──────────▼────────────▼──────────────▼───────┐
│        Detection & Analysis Results              │
└──────────────────┬───────────────────────────────┘
                   │
        ┌──────────▼──────────┐
        │  Automated Response │
        │  (Block/Alert/Fix)  │
        └─────────────────────┘
```

## 🚀 Getting Started

### Prerequisites
- **Java 25** (with preview features enabled) - [Download here](https://jdk.java.net/25/)
- **Maven 3.9+**
- Network access for vulnerability database queries (optional)

### Installation

```bash
# Clone the repository
git clone https://github.com/maaahhdiii/javashild.git
cd javashild
```

### Quick Start - Windows

**Option 1: One-Click Launch** (Recommended)
```batch
# Double-click or run in terminal:
run.bat
```

**Option 2: Interactive Menu**
```batch
# Launch interactive menu with multiple options:
start.bat
```

### Quick Start - Manual

```bash
# Build the project
mvn clean package -DskipTests

# Run the web application
mvn spring-boot:run

# Access the web interface
# Open browser: http://localhost:8080
```

### Command-Line Demo

```bash
# Run CLI demo with all 4 agents
java --enable-preview -cp target/vulnerability-detection-agent-1.0.0.jar com.security.ai.SecurityAgentDemo
```

## 💻 Usage Examples

### Auto-Fix Workflow (Web UI) 🆕

1. **Analyze Code**:
   - **Option A**: Paste Java code in "Code Analysis" tab
   - **Option B**: Upload .java file in "File Upload" tab

2. **Review Findings**: View detected vulnerabilities with severity and confidence scores

3. **Apply Auto-Fix**:
   - Click "Apply Auto-Fix" button on any finding with ✅ auto-fix support
   - View side-by-side diff showing original and fixed code
   - Read inline security comments explaining each change

4. **Copy Fixed Code**: Use copy button to export remediated code to clipboard

5. **Deploy**: Replace original code with fixed version

**Example Auto-Fix for SQL Injection:**
```java
// BEFORE (Vulnerable)
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// AFTER (Fixed with Auto-Fix)
// SECURITY FIX: Use PreparedStatement to prevent SQL injection
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, userId);
ResultSet rs = stmt.executeQuery();
```

### Programmatic Usage

```java
// Initialize orchestrator
AgentOrchestrator orchestrator = new AgentOrchestrator();

// Register agents
orchestrator.registerAgent(new StaticAnalysisAgent());
orchestrator.registerAgent(new DynamicAnalysisAgent());
orchestrator.registerAgent(new MLClassificationAgent());
orchestrator.registerAgent(new AutomatedResponseAgent());

// Start all agents
orchestrator.startAll();

// Analyze code
SecurityAgent.SecurityEvent event = new SecurityAgent.SecurityEvent(
    null, null,
    SecurityAgent.SecurityEvent.EventType.CODE_CHANGE,
    "MyApp",
    Paths.get("src/main/java/MyClass.java")
);

CompletableFuture<AgentOrchestrator.AggregatedFindings> result = 
    orchestrator.analyzeEvent(event);

// Process findings
result.thenAccept(findings -> {
    System.out.println("Found " + findings.findings().size() + " vulnerabilities");
    
    if (findings.hasBlockableThreats()) {
        System.out.println("CRITICAL: Blockable threats detected!");
    }
});

// Cleanup
orchestrator.stopAll();
```

### CI/CD Integration

#### Jenkins
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'java --enable-preview -jar vulnerability-detection-agent.jar --scan --path ${WORKSPACE}'
            }
        }
    }
}
```

#### GitHub Actions
```yaml
- name: Security Scan
  run: |
    java --enable-preview -jar vulnerability-detection-agent.jar \
      --scan --path ${{ github.workspace }}
```

## 🔧 Configuration

### Agent Configuration

Create `agent-config.json`:

```json
{
  "staticAnalysis": {
    "enabled": true,
    "minConfidence": 0.7,
    "scanTestFiles": false
  },
  "dynamicAnalysis": {
    "enabled": true,
    "monitoringInterval": 5000
  },
  "mlClassification": {
    "enabled": true,
    "modelPath": "models/vulnerability-classifier.model",
    "retrainingThreshold": 100
  },
  "automatedResponse": {
    "enabled": true,
    "failOnCritical": true,
    "maxHighSeverity": 5
  }
}
```

## 📊 Supported Vulnerability Types

### Static Analysis Detection (9 Types - All with Auto-Fix)
- ✅ **SQL Injection** (CWE-89): PreparedStatement conversion
- ✅ **Cross-Site Scripting (XSS)**: HTML escaping implementation
- ✅ **Insecure Deserialization** (CWE-502): JSON serialization migration
- ✅ **Path Traversal** (CWE-22): Path normalization with security
- ✅ **Command Injection** (CWE-78): ProcessBuilder with security controls
- ✅ **XXE Injection** (CWE-611): Secure XML parsing configuration
- ✅ **Hardcoded Credentials** (CWE-798): Environment variable migration
- ✅ **Insecure Cryptography** (CWE-327): Strong algorithm replacement (MD5→SHA-256, DES→AES)
- ✅ **Network/SSL/TLS Issues** (CWE-295): HTTPS and TLS 1.3 enforcement

### Dynamic Analysis Detection (6 Types)
- 🔍 **HTTP (Non-HTTPS) Connections** (CWE-319): Unencrypted communication detection
- 🔍 **Weak TLS/SSL Configurations**: Protocol version analysis
- 🔍 **Missing Certificate Validation**: Security check bypass detection
- 🔍 **Suspicious Network Destinations**: Domain reputation analysis (.ru, .cn, .tk, etc.)
- 🔍 **Sensitive File Access** (CWE-200): Data exposure monitoring
- 🔍 **API Security Issues**: Endpoint security assessment

### Dependency Vulnerabilities
- ✅ CVE Database Integration
- ✅ OWASP Dependency Check
- ✅ NVD API Integration

## 📈 Performance Benchmarks

| Operation | Time (avg) | Throughput |
## 🛠️ Technology Stack

- **Java 25**: Virtual threads, structured concurrency, pattern matching
- **Spring Boot 3.4.0**: Web framework, REST API, embedded Tomcat
- **Frontend**: HTML5, CSS3, JavaScript (ES6+), Font Awesome
- **ML Framework**: Tribuo 4.3.1
- **Static Analysis**: SpotBugs, PMD, JavaParser
- **Vulnerability DB**: NVD API, OWASP Dependency-Check
- **Build Tool**: Maven 3.9+
## 🔬 Project Structure

```
javashild/
├── src/main/java/com/security/ai/
│   ├── agent/                      # Core agent framework
│   │   ├── SecurityAgent.java
│   │   ├── AbstractSecurityAgent.java
│   │   └── AgentOrchestrator.java
│   ├── analysis/
│   │   ├── staticanalysis/        # Static code analysis
│   │   └── dynamicanalysis/       # Runtime analysis
│   ├── ml/                        # ML classification
│   ├── response/                  # Automated response
│   ├── vulnerabilitydb/          # Vulnerability databases
│   ├── integration/              # CI/CD integration
│   ├── web/                      # Spring Boot web application
│   │   ├── SecurityAgentWebApplication.java
│   │   ├── controller/           # REST API controllers
│   │   └── dto/                  # Data transfer objects
│   └── SecurityAgentDemo.java    # CLI demo application
├── src/main/resources/
│   ├── application.properties    # Spring Boot configuration
│   ├── logback.xml              # Logging configuration
│   └── static/
│       └── index.html           # Professional web UI
├── run.bat                      # One-click launcher (Windows)
├── start.bat                    # Interactive menu (Windows)
├── pom.xml                      # Maven configuration
└── README.md                    # This file
``` │   └── dynamicanalysis/       # Runtime analysis
│   ├── ml/                        # ML classification
│   ├── response/                  # Automated response
│   ├── vulnerabilitydb/          # Vulnerability databases
│   ├── integration/              # CI/CD integration
│   └── SecurityAgentDemo.java    # Main demo application
├── src/main/resources/
│   └── logback.xml               # Logging configuration
├── pom.xml                       # Maven configuration
└── README.md                     # This file
```

## 🧪 Testing

## 🌐 Web Interface Features

Access the professional web UI at `http://localhost:8080` after starting the application:

### Dashboard
- **Real-time Statistics**: Active agents, total scans, threats blocked
- **System Health**: Live agent status monitoring
- **4 Security Agents**: Static Analyzer, Dynamic Analyzer, ML Classifier, Response Handler

### Analysis Tools
1. **Code Analysis Tab**: Paste Java code for instant vulnerability detection
2. **File Upload Tab**: Drag-and-drop .java files for comprehensive scanning
3. **Network Scan Tab**: Test network requests for security issues (supports full URL input)
4. **Agent Status Panel**: Monitor all agents with health metrics

### Auto-Fix Features 🆕
- **One-Click Remediation**: Automatically generate fixes for 9 vulnerability types
- **Interactive Diff Viewer**: Side-by-side before/after comparison with syntax highlighting
- **Security Comments**: Inline explanations embedded in fixed code
- **Copy Function**: Quick clipboard export of remediated code
- **Multi-Path Support**: Works with textarea input and file uploads

### Network Scan Enhancements 🆕
- **Smart URL Parsing**: Paste full URLs like `http://example.com` - auto-extracts protocol and hostname
- **Real-time Analysis**: Instant HTTP/HTTPS security checks
- **Recommendation System**: Detailed security guidance for network issues

### Example Analysis Results with Auto-Fix
```json
{
  "totalFindings": 3,
  "criticalCount": 1,
  "highCount": 2,
  "findings": [
    {
      "category": "SQL_INJECTION",
      "severity": "CRITICAL",
      "description": "Potential SQL injection vulnerability detected",
      "location": "Example.java:5",
      "confidence": 0.90,
      "autoFixAvailable": true,
      "recommendations": [
        "Use PreparedStatement with parameterized queries",
        "Implement input validation and sanitization"
      ]
    }
  ]
}
```

## 📝 CLI Example Output

```
================================================================================
JavaShield - AI Security Platform
Java 25 - Advanced Security Automation System
================================================================================

Step 1: Initializing Security Agents...
✓ Registered 4 security agents

Step 2: Starting All Agents...
## 🎨 UI Screenshots

The web interface features:
- **Modern Design**: Clean, professional layout with Inter font
- **Purple Gradient Theme**: Eye-catching color scheme
- **Responsive Cards**: Animated hover effects
- **Real-time Updates**: Auto-refresh every 5 seconds
- **Font Awesome Icons**: Professional iconography throughout
- **Severity Badges**: Color-coded vulnerability indicators

## 🚀 What's New

### Version 1.0.0
- ✅ **Auto-Fix System**: One-click remediation for 9 vulnerability types with intelligent code transformation
- ✅ **Smart URL Parsing**: Network scan accepts full URLs with automatic protocol/hostname extraction
- ✅ **Interactive Diff Viewer**: Visual before/after comparison with syntax highlighting
- ✅ **Multi-Path Support**: Auto-fix works seamlessly with code textarea and file uploads
- ✅ Complete Java 25 support with structured concurrency and virtual threads
- ✅ Professional web interface with REST API endpoints
- ✅ Spring Boot 3.4.0 integration with modern architecture
- ✅ 4 autonomous AI agents for comprehensive security coverage
- ✅ Real-time vulnerability detection with ML-enhanced confidence scoring
- ✅ One-click Windows launcher scripts for easy deployment
- ✅ Interactive analysis dashboard with live agent monitoring

## 📧 Contact & Support

- **Repository**: [github.com/maaahhdiii/javashild](https://github.com/maaahhdiii/javashild)
- **Issues**: Open an issue on GitHub for bug reports or feature requests

---

**⚠️ Disclaimer**: This is an advanced security tool. Always test in a safe environment before deploying to production systems.

**🌟 Star this repo** if you find it useful!
  → Hardcoded Credentials [HIGH] - Confidence: 0.75
  → Insecure Deserialization [HIGH] - Confidence: 0.80

Demo 2: ML Model Training
--------------------------------------------------------------------------------
Training accuracy: 100.0%
Model ready for classification

...
``` Insecure Deserialization [HIGH] - Confidence: 0.80
Critical findings: 1
High severity findings: 2

Demo 2: Runtime Behavior Monitoring
--------------------------------------------------------------------------------
Analyzed network request to: suspicious-domain.ru
Security findings: 1
⚠ BLOCKABLE THREATS DETECTED - Automated response will be triggered

...
```

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

## 🔗 References

- [Java 25 Documentation](https://jdk.java.net/25/)
- [Tribuo ML Library](https://tribuo.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NVD API](https://nvd.nist.gov/developers)
- [CVE Database](https://cve.mitre.org/)

## 📧 Contact

For questions and support, please open an issue on GitHub.

---

**⚠️ Disclaimer**: This is an advanced security tool. Always test in a safe environment before deploying to production systems.
