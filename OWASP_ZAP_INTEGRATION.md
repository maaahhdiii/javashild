# OWASP ZAP Integration - Complete ✅

## Overview
Successfully integrated OWASP ZAP as an alternative dynamic scanner alongside MCP Kali Tools with UI-based scanner selection.

## What Was Added

### 1. **OwaspZapNativeScanner.java** (NEW)
- **Location**: `src/main/java/com/security/ai/unified/OwaspZapNativeScanner.java`
- **Purpose**: Native OWASP ZAP API integration
- **Connection**: `localhost:8090` (default ZAP API port)
- **Scanning Process**:
  - [1/4] 🌐 Access target URL
  - [2/4] 🕷️ Spider scan (web crawling)
  - [3/4] 👁️ Passive scan (traffic analysis)
  - [4/4] ⚡ Active scan (vulnerability testing)
- **Features**:
  - Progress tracking with percentages
  - Alert parsing and security finding generation
  - Graceful degradation if ZAP offline
  - Automatic reconnection support

### 2. **UnifiedMLSecurityAgent.java** (MODIFIED)
- **Dual Scanner Support**:
  - `mcpKaliScanner` - Existing MCP Kali Tools (7 scanners)
  - `owaspZapScanner` - New OWASP ZAP Native scanner
- **Scanner Mode**: `dynamicScannerMode` (default: "mcp")
- **Dynamic Switching**: API-based scanner selection
- **Initialization**: Both scanners initialized at startup
- **Scan Logic**: Routes to active scanner based on mode

### 3. **SecurityAgentController.java** (MODIFIED)
- **New Endpoints**:
  - `GET /api/security/scanner/status` - Returns scanner availability
  - `POST /api/security/scanner/switch` - Switches between scanners
- **Response Format**:
```json
{
  "currentMode": "mcp",
  "owaspZapAvailable": false,
  "scanners": [
    {
      "id": "mcp",
      "name": "MCP Kali Tools",
      "active": true,
      "available": true,
      "tools": ["Nmap", "Nikto", "Dirb", "SQLMap", "WPScan", "Security Headers", "SearchSploit"]
    },
    {
      "id": "owasp",
      "name": "OWASP ZAP Native",
      "active": false,
      "available": false,
      "tools": ["Spider Scan", "Passive Scan", "Active Scan", "Alert Analysis"]
    }
  ]
}
```

### 4. **index.html** (ENHANCED)
- **Visual Scanner Selection**:
  - Purple gradient container with 2 scanner option cards
  - **MCP Card**: Docker icon, "7 scanners", ACTIVE/AVAILABLE badge
  - **OWASP Card**: Shield icon, "4 tools", AVAILABLE/OFFLINE badge
- **JavaScript Functions**:
  - `loadScannerStatus()` - Fetches scanner status on page load
  - `updateScannerUI(status)` - Updates UI based on active scanner
  - `switchScanner(mode)` - Switches scanner with API call
- **Dynamic Loading Message**: Shows current scanner name during scans
- **Animated Notifications**: Success/error messages with auto-dismiss

## How to Use

### Prerequisites
1. **Java 25** with preview features enabled
2. **Maven 3.9+**
3. **Docker** (for MCP Kali Tools)
4. **OWASP ZAP** (optional - for OWASP scanner mode)

### Starting OWASP ZAP

#### Option 1: Daemon Mode (Headless)
```bash
zap.sh -daemon -host localhost -port 8090 -config api.key=none
```

#### Option 2: GUI Mode
1. Launch OWASP ZAP GUI
2. Go to Tools → Options → API
3. Enable API, set port to 8090
4. Disable API key (or set `api.key` in config)

#### Windows:
```powershell
& "C:\Program Files\OWASP\Zed Attack Proxy\ZAP.exe" -daemon -host localhost -port 8090 -config api.key=none
```

### Starting JavaShield
```bash
cd d:\jabaproj
d:\.jdk\jdk-25\bin\java.exe --enable-preview -jar target/vulnerability-detection-agent-1.0.0.jar
```

### Scanner Status Detection
- On startup, JavaShield checks both scanners:
  - **MCP**: Checks Docker container `kali-security-mcp-server:latest`
  - **OWASP**: Attempts connection to `localhost:8090`
- UI automatically reflects availability:
  - ACTIVE: Currently selected scanner
  - AVAILABLE: Ready to use
  - OFFLINE: Not available (Docker stopped or ZAP not running)

### Switching Scanners
1. Open http://localhost:8080
2. Navigate to "Website Scan" tab
3. Click on desired scanner card (MCP or OWASP)
4. Success notification confirms switch
5. Run scan to use new scanner

## Scanner Comparison

| Feature | MCP Kali Tools | OWASP ZAP Native |
|---------|----------------|------------------|
| **Technology** | Docker + JSON-RPC | Native Java API |
| **Tools** | 7 scanners (Nmap, Nikto, etc.) | 4 phases (Spider, Passive, Active) |
| **Progress** | [X/7] tool count | [X/4] phase percentage |
| **Setup** | Docker required | ZAP installation required |
| **Performance** | Fast, parallel execution | Thorough, sequential phases |
| **Best For** | Quick multi-tool scan | Deep web app analysis |

## Testing

### Without OWASP ZAP:
1. Start JavaShield (MCP only)
2. Verify:
   - MCP card shows **ACTIVE**
   - OWASP card shows **OFFLINE**
   - Clicking OWASP shows error: "OWASP ZAP is not available"
3. Run scan → Uses MCP tools

### With OWASP ZAP:
1. Start OWASP ZAP on port 8090
2. Restart JavaShield
3. Verify:
   - MCP card shows **ACTIVE**
   - OWASP card shows **AVAILABLE**
4. Click OWASP card → Switch success
5. Run scan → Uses OWASP ZAP (see [1/4] through [4/4] progress)
6. Check findings → "DYNAMIC: OWASP-ZAP" detection source

## Logs to Watch

### Startup:
```
✓ MCP Kali Tools Scanner initialized (Docker: kali-security-mcp-server:latest)
✓ OWASP ZAP Native Scanner initialized (localhost:8090)
Dynamic Analyzers: MCP [ACTIVE], OWASP ZAP Native [AVAILABLE]
```

### Scanner Switch:
```
Switched dynamic scanner from mcp to owasp
Dynamic Analyzers: MCP [AVAILABLE], OWASP ZAP Native [ACTIVE]
```

### OWASP Scan:
```
🔍 Starting OWASP ZAP scan for: http://example.com
[1/4] 🌐 Accessing URL: http://example.com
[2/4] 🕷️ Spider scan in progress: 45%
[3/4] 👁️ Passive scan in progress: 78%
[4/4] ⚡ Active scan in progress: 92%
✅ OWASP ZAP scan complete: 15 findings
```

## Architecture Decisions

### Why Dual Scanner?
- **Flexibility**: Different tools for different needs
- **Fallback**: If OWASP unavailable, MCP still works
- **Learning**: ML model learns from both scanner types
- **User Choice**: Some prefer MCP's speed, others prefer ZAP's depth

### Why Native ZAP API?
- **Performance**: Direct Java API faster than Docker/MCP layer
- **Control**: Fine-grained control over scan phases
- **Integration**: Better error handling and progress tracking
- **Simplicity**: No additional Docker container needed

### Default to MCP?
- **Backwards Compatibility**: Existing users expect MCP
- **Setup**: MCP Docker container already required
- **Reliability**: Docker ensures consistent environment

## Next Steps

### Enhancements:
- [ ] Add scanner configuration UI (ZAP host/port, MCP image)
- [ ] Save scanner preference to localStorage
- [ ] Add scan history per scanner
- [ ] Compare findings between scanners
- [ ] Merge findings from both scanners in single scan
- [ ] Add ZAP scan policies (Quick/Full/Custom)
- [ ] Add authentication support for ZAP scans

### Documentation:
- [ ] Update README.md with OWASP prerequisite
- [ ] Add troubleshooting guide
- [ ] Create video demo of scanner switching

## Files Changed
- ✅ `src/main/java/com/security/ai/unified/OwaspZapNativeScanner.java` (NEW)
- ✅ `src/main/java/com/security/ai/unified/UnifiedMLSecurityAgent.java` (MODIFIED)
- ✅ `src/main/java/com/security/ai/controller/SecurityAgentController.java` (MODIFIED)
- ✅ `src/main/resources/static/index.html` (MODIFIED)
- ✅ `pom.xml` (zap-clientapi dependency already present)

## Build Status
✅ **BUILD SUCCESS** - All compilation errors resolved

## Ready to Test!
Start the server and test both scanner modes. Enjoy the flexibility of dual-scanner support! 🚀
