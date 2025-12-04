# OWASP ZAP Integration Guide for JavaShield AI Security Agent

## 🎯 What is OWASP ZAP?

**OWASP ZAP (Zed Attack Proxy)** is the world's most popular free security tool for finding vulnerabilities in web applications. It provides **dynamic security testing** that complements JavaShield's static analysis.

### Dynamic Security Testing with ZAP:
- ✅ **SQL Injection** - Real-time injection attack testing
- ✅ **Cross-Site Scripting (XSS)** - DOM and reflected XSS detection  
- ✅ **CSRF** - Cross-Site Request Forgery vulnerabilities
- ✅ **Authentication Bypass** - Session and auth weakness testing
- ✅ **Security Headers** - Missing security configurations
- ✅ **SSL/TLS Issues** - Certificate and protocol problems

## 📥 Installation

### Option 1: Automatic Download (Recommended)

1. **Visit**: https://www.zaproxy.org/download/
2. **Download**: ZAP 2.15.0 for Windows (Installer)
3. **Install**: Follow the installer (default location: `C:\Program Files\OWASP\Zed Attack Proxy`)

### Option 2: Portable Version

1. **Download**: ZAP 2.15.0 Cross Platform (ZIP)
2. **Extract**: To `C:\ZAP` or any folder
3. **Locate**: `zap.bat` file in the extracted folder

## 🚀 Quick Start

### Method 1: Use the Startup Script (Easiest)

```powershell
# Navigate to project directory
cd d:\jabaproj

# Run the ZAP starter script
.\START-OWASP-ZAP.ps1
```

The script will:
- ✅ Auto-detect ZAP installation
- ✅ Start ZAP in daemon mode on port 8090
- ✅ Configure API access automatically
- ✅ Wait for ZAP to be ready

### Method 2: Manual Start

```powershell
# Navigate to ZAP installation
cd "C:\Program Files\OWASP\Zed Attack Proxy"

# Start ZAP in daemon mode
.\zap.bat -daemon -port 8090 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

### Method 3: Background Process

```powershell
Start-Process -FilePath "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" `
              -ArgumentList "-daemon","-port","8090","-config","api.disablekey=true" `
              -WindowStyle Hidden
```

## ✅ Verify ZAP is Running

### Check if ZAP is running:
```powershell
# Test ZAP API
Invoke-WebRequest -Uri "http://localhost:8090" -UseBasicParsing
```

You should see: **"ZAP API"** in the response

### Check ZAP process:
```powershell
Get-Process -Name "java" | Where-Object {$_.MainWindowTitle -like "*ZAP*"}
```

## 🔄 Restart JavaShield with ZAP

After starting ZAP, restart your JavaShield server:

```powershell
# Stop current server
Stop-Process -Name java -Force -ErrorAction SilentlyContinue

# Wait for cleanup
Start-Sleep 2

# Start JavaShield
d:\.jdk\jdk-25\bin\java.exe --enable-native-access=ALL-UNNAMED --enable-preview -jar target/vulnerability-detection-agent-1.0.0.jar
```

Look for this in the logs:
```
✓ OWASP ZAP Scanner connected (localhost:8090)
```

## 📊 Expected Results

### Without ZAP:
```
⚠️ OWASP ZAP not running on localhost:8090. Dynamic scanning disabled.
Detection Sources: STATIC: CustomAST, STATIC: PMD, STATIC: JQAssistant
```

### With ZAP Running:
```
✓ OWASP ZAP Scanner connected (localhost:8090)
Detection Sources: STATIC: CustomAST, STATIC: PMD, STATIC: JQAssistant, DYNAMIC: OWASP ZAP
```

## 🎨 Testing Dynamic Analysis

Once ZAP is running, analyze code that makes HTTP requests:

```java
public class WebApp {
    public void fetchData(String userId) throws IOException {
        // This will trigger ZAP's dynamic analysis
        URL url = new URL("http://api.example.com/user/" + userId);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // ... rest of code
    }
}
```

JavaShield will:
1. ✅ Detect the HTTP request (CustomAST - static)
2. ✅ Send URL to ZAP for active scanning
3. ✅ ZAP tests for injection, XSS, auth issues
4. ✅ Return findings with "DYNAMIC: OWASP ZAP" label

## 🛑 Stop ZAP

```powershell
# Stop ZAP daemon
Stop-Process -Name "java" -Force

# Or be more specific
Get-Process | Where-Object {$_.MainWindowTitle -like "*ZAP*"} | Stop-Process
```

## 🔧 Troubleshooting

### Issue: "ZAP not running" warning
**Solution**: 
1. Verify ZAP process: `Get-Process -Name java`
2. Check port 8090: `Test-NetConnection -ComputerName localhost -Port 8090`
3. Try manual start with verbose output: `.\zap.bat -daemon -port 8090`

### Issue: Port 8090 already in use
**Solution**:
```powershell
# Find what's using port 8090
Get-NetTCPConnection -LocalPort 8090 | Select-Object OwningProcess

# Kill the process
Stop-Process -Id <ProcessID> -Force
```

### Issue: ZAP starts but immediately closes
**Solution**:
1. Check Java installation: `java -version`
2. ZAP requires Java 11 or later
3. Set JAVA_HOME: `$env:JAVA_HOME="d:\.jdk\jdk-25"`

### Issue: "Connection refused" when accessing ZAP API
**Solution**:
- ZAP takes 20-30 seconds to start
- Wait longer or check ZAP logs in: `%USERPROFILE%\.ZAP\zap.log`

## 📚 Advanced Configuration

### Custom API Key (More Secure)

```powershell
# Start ZAP with API key
.\zap.bat -daemon -port 8090 -config api.key=your-secret-key
```

Then update `OWASPZAPScanner.java`:
```java
private static final String ZAP_API_KEY = "your-secret-key";
```

### Different Port

```powershell
# Use port 9090 instead
.\zap.bat -daemon -port 9090 -config api.disablekey=true
```

Update `OWASPZAPScanner.java`:
```java
private static final int ZAP_PORT = 9090;
```

### Scan Specific Target

ZAP can scan a live web application:
```powershell
# Start ZAP
.\zap.bat -daemon -port 8090 -config api.disablekey=true

# Scan a target (using ZAP CLI)
zap-cli quick-scan --self-contained http://localhost:8080
```

## 🎓 Best Practices

1. **Start ZAP first** - Before starting JavaShield
2. **Allow time** - ZAP needs 20-30 seconds to initialize
3. **Monitor logs** - Check ZAP logs for errors: `%USERPROFILE%\.ZAP\zap.log`
4. **Resource usage** - ZAP uses ~1GB RAM, ensure adequate memory
5. **Firewall** - Add exception for ZAP if needed
6. **Regular updates** - Keep ZAP updated: https://www.zaproxy.org/download/

## 📖 More Information

- **ZAP Documentation**: https://www.zaproxy.org/docs/
- **ZAP API**: https://www.zaproxy.org/docs/api/
- **ZAP Desktop UI**: Start without `-daemon` flag to see GUI
- **ZAP Community**: https://groups.google.com/group/zaproxy-users

## ✨ Summary

```
1. Download ZAP → https://www.zaproxy.org/download/
2. Install ZAP → Default location
3. Run Script → .\START-OWASP-ZAP.ps1
4. Wait 30s → For ZAP to initialize
5. Start JavaShield → Dynamic scanning enabled! 🚀
```

**Result**: Your JavaShield Security Agent now performs **6 types of analysis**:
- STATIC: CustomAST ✅
- STATIC: PMD ✅
- STATIC: JQAssistant ✅  
- STATIC: SpotBugs ✅
- **DYNAMIC: OWASP ZAP ✅** ← **NEW!**
- Runtime Monitor ✅

---

**Need Help?** Open an issue or check ZAP logs at: `%USERPROFILE%\.ZAP\zap.log`
