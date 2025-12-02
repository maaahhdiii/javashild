# Quick Start Guide
## AI Agent for Vulnerability Detection

### Prerequisites
- Java 25 (https://jdk.java.net/25/)
- Maven 3.9+ (https://maven.apache.org/)
- 4GB RAM minimum
- Network connection (optional, for NVD API)

---

## 🚀 5-Minute Quick Start

### 1. Build the Project

**Windows:**
```cmd
build.bat
```

**Linux/macOS:**
```bash
chmod +x build.sh
./build.sh
```

### 2. Run the Demo

```bash
java --enable-preview -jar dist/vulnerability-detection-agent-1.0.0.jar
```

**Expected Output:**
```
================================================================================
AI Agent for Vulnerability Detection, Handling and Blocking
Java 25 - Advanced Security Automation System
================================================================================

Step 1: Initializing Security Agents...
✓ Registered 4 security agents

Demo 1: Static Code Analysis
Found 3 potential vulnerabilities
  → SQL Injection [CRITICAL] - Confidence: 0.90
  ...
```

### 3. Scan Your Project

```bash
java --enable-preview -jar dist/vulnerability-detection-agent-1.0.0.jar \
  --scan --path /path/to/your/project
```

---

## 📋 Common Use Cases

### Use Case 1: CI/CD Integration

**Generate Jenkins Pipeline:**
```bash
java --enable-preview -jar vulnerability-detection-agent.jar --cicd > Jenkinsfile
```

**Add to GitHub Actions:**
```yaml
# .github/workflows/security-scan.yml
- name: Security Scan
  run: |
    java --enable-preview -jar vulnerability-detection-agent.jar \
      --scan --path ${{ github.workspace }}
```

### Use Case 2: Pre-Commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
java --enable-preview -jar vulnerability-detection-agent.jar \
  --scan --path . || exit 1
```

### Use Case 3: Live Monitoring

```bash
java --enable-preview -jar vulnerability-detection-agent.jar --monitor
```

---

## 🔧 Configuration

### Custom Configuration

Create `agent-config.json`:

```json
{
  "staticAnalysis": {
    "enabled": true,
    "minConfidence": 0.8,
    "scanTestFiles": false
  },
  "automatedResponse": {
    "failOnCritical": true,
    "maxHighSeverity": 3
  }
}
```

### Environment Variables

```bash
export SECURITY_AGENT_LOG_LEVEL=DEBUG
export NVD_API_KEY=your-api-key-here
export ENABLE_AUTO_REMEDIATION=true
```

---

## 📊 Output Formats

### JSON Output
```bash
java --enable-preview -jar vulnerability-detection-agent.jar \
  --scan --path . --output results.json --format json
```

### SARIF (for GitHub Code Scanning)
```bash
java --enable-preview -jar vulnerability-detection-agent.jar \
  --scan --path . --output results.sarif --format sarif
```

### HTML Report
```bash
java --enable-preview -jar vulnerability-detection-agent.jar \
  --scan --path . --output report.html --format html
```

---

## 🐛 Troubleshooting

### Issue: "Java 25 not found"
**Solution:**
```bash
# Download and extract Java 25
# Set JAVA_HOME
export JAVA_HOME=/path/to/jdk-25
export PATH=$JAVA_HOME/bin:$PATH
```

### Issue: "Preview features not enabled"
**Solution:**
Add `--enable-preview` flag:
```bash
java --enable-preview -jar vulnerability-detection-agent.jar
```

### Issue: "Maven build fails"
**Solution:**
```bash
# Clean and rebuild
mvn clean install -U
```

### Issue: "Out of memory"
**Solution:**
```bash
# Increase heap size
java --enable-preview -Xmx4g -jar vulnerability-detection-agent.jar
```

---

## 📈 Performance Tuning

### For Large Projects
```bash
# Increase memory and threads
java --enable-preview \
  -Xmx8g \
  -XX:ActiveProcessorCount=8 \
  -jar vulnerability-detection-agent.jar \
  --scan --path /large/project
```

### For Fast Scanning
```bash
# Skip dynamic analysis for speed
java --enable-preview -jar vulnerability-detection-agent.jar \
  --scan --path . --skip-dynamic
```

---

## 🔐 Security Best Practices

1. **Run in isolated environment** for untrusted code
2. **Review findings** before automated blocking
3. **Use API keys** for NVD access (rate limits)
4. **Enable logging** for audit trail
5. **Test in staging** before production deployment

---

## 📚 Next Steps

1. Read [README.md](README.md) for detailed documentation
2. Review [ARCHITECTURE.md](ARCHITECTURE.md) for design details
3. See [PRESENTATION.md](PRESENTATION.md) for PPT content
4. Check [FUTURE.md](FUTURE.md) for roadmap

---

## 💬 Getting Help

- **Documentation**: See README.md
- **Issues**: Open GitHub issue
- **Examples**: Check `examples/` directory
- **Logs**: See `logs/security-agent.log`

---

## ✅ Quick Checklist

- [ ] Java 25 installed
- [ ] Maven installed
- [ ] Project built successfully
- [ ] Demo runs without errors
- [ ] Scanned sample project
- [ ] Reviewed findings
- [ ] Integrated with CI/CD (optional)

---

**🎉 You're all set! Start securing your code with AI-powered vulnerability detection.**
