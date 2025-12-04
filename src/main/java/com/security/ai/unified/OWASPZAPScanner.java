package com.security.ai.unified;

import com.security.ai.agent.SecurityAgent;
import com.security.ai.analysis.dynamicanalysis.DynamicAnalysisAgent.NetworkRequestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * MCP Kali Tools Scanner - Dynamic Security Testing via Docker MCP Toolkit
 * 
 * Uses Docker MCP Toolkit Gateway (stdio) with Kali Linux security tools:
 * - nmap_scan - Network scanning and port discovery
 * - nikto_scan - Web server vulnerability scanning
 * - sqlmap_test - SQL injection detection and exploitation
 * - dirb_scan - Directory brute forcing
 * - wpscan_scan - WordPress vulnerability scanner
 * - security_headers_check - HTTP security headers analysis
 * - searchsploit_search - Exploit database search
 */
public class OWASPZAPScanner {
    
    private static final Logger logger = LoggerFactory.getLogger(OWASPZAPScanner.class);
    
    private boolean mcpConnected = false;
    private Process mcpGatewayProcess = null;
    private BufferedWriter mcpStdin = null;
    private BufferedReader mcpStdout = null;
    private AtomicInteger requestIdCounter = new AtomicInteger(1);
    
    public void initialize() {
        try {
            logger.info("Initializing MCP Kali Tools Scanner (Docker Toolkit Gateway)...");
            
            // Start MCP gateway process with stdio communication
            try {
                ProcessBuilder pb = new ProcessBuilder("docker", "run", "-i", "--rm", "kali-security-mcp-server:latest");
                pb.redirectErrorStream(false); // Keep stderr separate
                
                mcpGatewayProcess = pb.start();
                
                mcpStdin = new BufferedWriter(
                    new OutputStreamWriter(mcpGatewayProcess.getOutputStream(), StandardCharsets.UTF_8));
                mcpStdout = new BufferedReader(
                    new InputStreamReader(mcpGatewayProcess.getInputStream(), StandardCharsets.UTF_8));
                
                // Wait a moment for gateway to initialize
                Thread.sleep(2000);
                
                // Step 1: Initialize MCP session
                logger.info("Sending MCP initialize request...");
                JSONObject initRequest = new JSONObject();
                initRequest.put("jsonrpc", "2.0");
                initRequest.put("id", requestIdCounter.getAndIncrement());
                initRequest.put("method", "initialize");
                
                JSONObject initParams = new JSONObject();
                initParams.put("protocolVersion", "2024-11-05");
                
                JSONObject clientInfo = new JSONObject();
                clientInfo.put("name", "JavaShield");
                clientInfo.put("version", "1.0.0");
                initParams.put("clientInfo", clientInfo);
                
                JSONObject capabilities = new JSONObject();
                capabilities.put("tools", new JSONObject());
                initParams.put("capabilities", capabilities);
                
                initRequest.put("params", initParams);
                
                String initResponse = sendMCPRequest(initRequest);
                
                if (initResponse != null && initResponse.contains("capabilities")) {
                    logger.info("MCP session initialized successfully");
                    
                    // Step 2: Send initialized notification
                    JSONObject initializedNotif = new JSONObject();
                    initializedNotif.put("jsonrpc", "2.0");
                    initializedNotif.put("method", "notifications/initialized");
                    initializedNotif.put("params", new JSONObject());
                    
                    mcpStdin.write(initializedNotif.toString() + "\n");
                    mcpStdin.flush();
                    
                    // Step 3: List tools to confirm connection
                    JSONObject listToolsRequest = new JSONObject();
                    listToolsRequest.put("jsonrpc", "2.0");
                    listToolsRequest.put("id", requestIdCounter.getAndIncrement());
                    listToolsRequest.put("method", "tools/list");
                    listToolsRequest.put("params", new JSONObject());
                    
                    String toolsResponse = sendMCPRequest(listToolsRequest);
                    
                    logger.info("MCP tools/list response: {}", toolsResponse);
                    
                    if (toolsResponse != null && toolsResponse.contains("tools")) {
                        mcpConnected = true;
                        logger.info("✓ MCP Kali Tools Scanner connected (Docker MCP Gateway)");
                        
                        // Parse and log actual tool names
                        try {
                            JSONObject toolsJson = new JSONObject(toolsResponse);
                            if (toolsJson.has("result") && toolsJson.getJSONObject("result").has("tools")) {
                                JSONArray toolsArray = toolsJson.getJSONObject("result").getJSONArray("tools");
                                if (toolsArray.length() == 0) {
                                    logger.warn("⚠ MCP Gateway has NO TOOLS available!");
                                    logger.warn("  Please configure Kali tools in your MCP Docker setup");
                                    mcpConnected = false;
                                } else {
                                    StringBuilder toolNames = new StringBuilder("  → Available tools: ");
                                    for (int i = 0; i < toolsArray.length(); i++) {
                                        JSONObject tool = toolsArray.getJSONObject(i);
                                        if (i > 0) toolNames.append(", ");
                                        toolNames.append(tool.getString("name"));
                                    }
                                    logger.info(toolNames.toString());
                                }
                            }
                        } catch (Exception e) {
                            logger.warn("Could not parse tool names from response: {}", toolsResponse, e);
                        }
                    } else {
                        logger.warn("MCP Gateway started but tools list failed");
                        mcpConnected = false;
                    }
                } else {
                    logger.warn("MCP initialization failed");
                    mcpConnected = false;
                }
                
            } catch (Exception e) {
                logger.warn("Docker MCP Toolkit not available. Dynamic scanning disabled.");
                logger.warn("To enable: Ensure 'docker mcp client connect vscode' is configured");
                mcpConnected = false;
            }
            
        } catch (Exception e) {
            logger.error("Failed to initialize MCP Kali Tools Scanner", e);
            mcpConnected = false;
        }
    }
    
    private String sendMCPRequest(JSONObject request) {
        try {
            if (mcpStdin == null || mcpStdout == null) {
                logger.warn("MCP stdio streams not initialized, cannot send request");
                return null;
            }
            
            String requestStr = request.toString() + "\n";
            logger.debug("Sending MCP request: {}", request.getString("method"));
            
            mcpStdin.write(requestStr);
            mcpStdin.flush();
            
            // Wait for response without timeout - scan tools may take time
            while (!mcpStdout.ready()) {
                Thread.sleep(100);
            }
            
            if (mcpStdout.ready()) {
                String responseLine = mcpStdout.readLine();
                if (responseLine != null) {
                    logger.debug("Received MCP response: {} chars", responseLine.length());
                    return responseLine;
                }
            }
            
        } catch (Exception e) {
            logger.error("MCP request failed: {}", e.getMessage(), e);
        }
        return null;
    }
    
    public List<SecurityAgent.SecurityFinding> scanTarget(NetworkRequestInfo netInfo) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        if (!mcpConnected) {
            logger.warn("MCP server not connected - attempting scan anyway");
            // Don't return early - try to run scans anyway
        }
        
        try {
            String targetUrl = netInfo.protocol().toLowerCase() + "://" + netInfo.host();
            if (netInfo.port() != 80 && netInfo.port() != 443) {
                targetUrl += ":" + netInfo.port();
            }
            
            logger.info("=== MCP Kali Tools scanning: {} ===", targetUrl);
            
            // Determine total number of scans
            int totalScans = netInfo.protocol().equalsIgnoreCase("http") || netInfo.protocol().equalsIgnoreCase("https") ? 7 : 2;
            int currentScan = 0;
            
            // Run Nmap port scan via MCP stdio
            currentScan++;
            logger.info("[{}/{}] 📡 Starting Nmap scan...", currentScan, totalScans);
            List<SecurityAgent.SecurityFinding> nmapFindings = runNmapScan(targetUrl, netInfo.host(), netInfo.port());
            findings.addAll(nmapFindings);
            logger.info("[{}/{}] ✓ Nmap scan completed: {} findings", currentScan, totalScans, nmapFindings.size());
            
            // Run all web-based scans for HTTP/HTTPS targets
            if (netInfo.protocol().equalsIgnoreCase("http") || netInfo.protocol().equalsIgnoreCase("https")) {
                // Nikto web server scan
                currentScan++;
                logger.info("[{}/{}] 🔍 Starting Nikto scan...", currentScan, totalScans);
                List<SecurityAgent.SecurityFinding> niktoFindings = runNiktoScan(targetUrl);
                findings.addAll(niktoFindings);
                logger.info("[{}/{}] ✓ Nikto scan completed: {} findings", currentScan, totalScans, niktoFindings.size());
                
                // Dirb directory brute forcing
                currentScan++;
                logger.info("[{}/{}] 📂 Starting Dirb scan...", currentScan, totalScans);
                List<SecurityAgent.SecurityFinding> dirbFindings = runDirbScan(targetUrl);
                findings.addAll(dirbFindings);
                logger.info("[{}/{}] ✓ Dirb scan completed: {} findings", currentScan, totalScans, dirbFindings.size());
                
                // Security headers check
                currentScan++;
                logger.info("[{}/{}] 🔒 Starting Security Headers check...", currentScan, totalScans);
                List<SecurityAgent.SecurityFinding> headersFindings = runSecurityHeadersCheck(targetUrl);
                findings.addAll(headersFindings);
                logger.info("[{}/{}] ✓ Security Headers check completed: {} findings", currentScan, totalScans, headersFindings.size());
                
                // SQLMap SQL injection testing
                currentScan++;
                logger.info("[{}/{}] 💉 Starting SQLMap test...", currentScan, totalScans);
                List<SecurityAgent.SecurityFinding> sqlmapFindings = runSQLMapTest(targetUrl);
                findings.addAll(sqlmapFindings);
                logger.info("[{}/{}] ✓ SQLMap test completed: {} findings", currentScan, totalScans, sqlmapFindings.size());
                
                // WPScan for WordPress sites
                currentScan++;
                logger.info("[{}/{}] 🌐 Starting WPScan...", currentScan, totalScans);
                List<SecurityAgent.SecurityFinding> wpscanFindings = runWPScan(targetUrl);
                findings.addAll(wpscanFindings);
                logger.info("[{}/{}] ✓ WPScan completed: {} findings", currentScan, totalScans, wpscanFindings.size());
            }
            
            // SearchSploit exploit database search
            currentScan++;
            logger.info("[{}/{}] 🔎 Starting SearchSploit search...", currentScan, totalScans);
            List<SecurityAgent.SecurityFinding> searchsploitFindings = runSearchSploit(targetUrl);
            findings.addAll(searchsploitFindings);
            logger.info("[{}/{}] ✓ SearchSploit search completed: {} findings", currentScan, totalScans, searchsploitFindings.size());
            
            logger.info("=== MCP Kali Tools found {} total vulnerabilities in {} ===", findings.size(), targetUrl);
            
        } catch (Exception e) {
            logger.error("MCP Kali Tools scan failed for {}: {}", netInfo.host(), e.getMessage(), e);
        }
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> runNmapScan(String targetUrl, String host, int port) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            logger.debug("Running nmap_scan via MCP stdio for {}:{}", host, port);
            
            // Build MCP tools/call request
            JSONObject request = new JSONObject();
            request.put("jsonrpc", "2.0");
            request.put("id", requestIdCounter.getAndIncrement());
            request.put("method", "tools/call");
            
            JSONObject params = new JSONObject();
            params.put("name", "nmap_scan");
            
            JSONObject arguments = new JSONObject();
            arguments.put("target", host);
            arguments.put("port", String.valueOf(port));
            params.put("arguments", arguments);
            
            request.put("params", params);
            
            String response = sendMCPRequest(request);
            
            if (response != null) {
                findings.addAll(parseMCPToolResponse(response, "NMAP", targetUrl));
                logger.debug("Nmap scan completed, found {} findings", findings.size());
            }
            
        } catch (Exception e) {
            logger.debug("Nmap scan skipped: {}", e.getMessage());
        }
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> runNiktoScan(String targetUrl) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            logger.debug("Running nikto_scan via MCP stdio for {}", targetUrl);
            
            JSONObject request = new JSONObject();
            request.put("jsonrpc", "2.0");
            request.put("id", requestIdCounter.getAndIncrement());
            request.put("method", "tools/call");
            
            JSONObject params = new JSONObject();
            params.put("name", "nikto_scan");
            
            JSONObject arguments = new JSONObject();
            arguments.put("target", targetUrl);
            params.put("arguments", arguments);
            
            request.put("params", params);
            
            String response = sendMCPRequest(request);
            
            if (response != null) {
                findings.addAll(parseMCPToolResponse(response, "NIKTO", targetUrl));
                logger.debug("Nikto scan completed, found {} findings", findings.size());
            }
            
        } catch (Exception e) {
            logger.debug("Nikto scan skipped: {}", e.getMessage());
        }
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> runDirbScan(String targetUrl) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            logger.debug("Running dirb_scan via MCP stdio for {}", targetUrl);
            
            JSONObject request = new JSONObject();
            request.put("jsonrpc", "2.0");
            request.put("id", requestIdCounter.getAndIncrement());
            request.put("method", "tools/call");
            
            JSONObject params = new JSONObject();
            params.put("name", "dirb_scan");
            
            JSONObject arguments = new JSONObject();
            arguments.put("target", targetUrl);
            params.put("arguments", arguments);
            
            request.put("params", params);
            
            String response = sendMCPRequest(request);
            
            if (response != null) {
                findings.addAll(parseMCPToolResponse(response, "DIRB", targetUrl));
                logger.debug("Dirb scan completed, found {} findings", findings.size());
            }
            
        } catch (Exception e) {
            logger.debug("Dirb scan skipped: {}", e.getMessage());
        }
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> runSecurityHeadersCheck(String targetUrl) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            logger.debug("Running security_headers_check via MCP stdio for {}", targetUrl);
            
            JSONObject request = new JSONObject();
            request.put("jsonrpc", "2.0");
            request.put("id", requestIdCounter.getAndIncrement());
            request.put("method", "tools/call");
            
            JSONObject params = new JSONObject();
            params.put("name", "security_headers_check");
            
            JSONObject arguments = new JSONObject();
            arguments.put("target", targetUrl);
            params.put("arguments", arguments);
            
            request.put("params", params);
            
            String response = sendMCPRequest(request);
            
            if (response != null) {
                findings.addAll(parseMCPToolResponse(response, "SECURITY-HEADERS", targetUrl));
                logger.debug("Security headers check completed, found {} findings", findings.size());
            }
            
        } catch (Exception e) {
            logger.debug("Security headers check skipped: {}", e.getMessage());
        }
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> runSQLMapTest(String targetUrl) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            logger.debug("Running sqlmap_test via MCP stdio for {}", targetUrl);
            
            JSONObject request = new JSONObject();
            request.put("jsonrpc", "2.0");
            request.put("id", requestIdCounter.getAndIncrement());
            request.put("method", "tools/call");
            
            JSONObject params = new JSONObject();
            params.put("name", "sqlmap_test");
            
            JSONObject arguments = new JSONObject();
            arguments.put("target", targetUrl);
            params.put("arguments", arguments);
            
            request.put("params", params);
            
            String response = sendMCPRequest(request);
            
            if (response != null) {
                findings.addAll(parseMCPToolResponse(response, "SQLMAP", targetUrl));
                logger.debug("SQLMap test completed, found {} findings", findings.size());
            }
            
        } catch (Exception e) {
            logger.debug("SQLMap test skipped: {}", e.getMessage());
        }
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> runWPScan(String targetUrl) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            logger.debug("Running wpscan_scan via MCP stdio for {}", targetUrl);
            
            JSONObject request = new JSONObject();
            request.put("jsonrpc", "2.0");
            request.put("id", requestIdCounter.getAndIncrement());
            request.put("method", "tools/call");
            
            JSONObject params = new JSONObject();
            params.put("name", "wpscan_scan");
            
            JSONObject arguments = new JSONObject();
            arguments.put("target", targetUrl);
            params.put("arguments", arguments);
            
            request.put("params", params);
            
            String response = sendMCPRequest(request);
            
            if (response != null) {
                findings.addAll(parseMCPToolResponse(response, "WPSCAN", targetUrl));
                logger.debug("WPScan completed, found {} findings", findings.size());
            }
            
        } catch (Exception e) {
            logger.debug("WPScan skipped: {}", e.getMessage());
        }
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> runSearchSploit(String targetUrl) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            logger.debug("Running searchsploit_search via MCP stdio for {}", targetUrl);
            
            JSONObject request = new JSONObject();
            request.put("jsonrpc", "2.0");
            request.put("id", requestIdCounter.getAndIncrement());
            request.put("method", "tools/call");
            
            JSONObject params = new JSONObject();
            params.put("name", "searchsploit_search");
            
            JSONObject arguments = new JSONObject();
            arguments.put("query", targetUrl);
            params.put("arguments", arguments);
            
            request.put("params", params);
            
            String response = sendMCPRequest(request);
            
            if (response != null) {
                findings.addAll(parseMCPToolResponse(response, "SEARCHSPLOIT", targetUrl));
                logger.debug("SearchSploit search completed, found {} findings", findings.size());
            }
            
        } catch (Exception e) {
            logger.debug("SearchSploit search skipped: {}", e.getMessage());
        }
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> parseMCPToolResponse(String response, String tool, String location) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            JSONObject jsonResponse = new JSONObject(response);
            
            // Check for MCP error
            if (jsonResponse.has("error")) {
                logger.debug("{} returned error: {}", tool, jsonResponse.getJSONObject("error").optString("message"));
                return findings;
            }
            
            // Extract result
            if (jsonResponse.has("result")) {
                Object result = jsonResponse.get("result");
                
                // Result could be array of content items (MCP protocol)
                if (result instanceof JSONArray) {
                    JSONArray contentArray = (JSONArray) result;
                    logger.debug("{} returned {} content items", tool, contentArray.length());
                    for (int i = 0; i < contentArray.length(); i++) {
                        JSONObject content = contentArray.getJSONObject(i);
                        if (content.has("text")) {
                            String text = content.getString("text");
                            logger.debug("{} content[{}]: {} chars", tool, i, text.length());
                            logger.debug("{} text preview: {}", tool, text.substring(0, Math.min(500, text.length())));
                            findings.addAll(parseToolOutputText(text, tool, location));
                        }
                    }
                } else if (result instanceof JSONObject) {
                    JSONObject resultObj = (JSONObject) result;
                    
                    // Check for vulnerabilities array
                    if (resultObj.has("vulnerabilities")) {
                        JSONArray vulns = resultObj.getJSONArray("vulnerabilities");
                        logger.info("{} found {} vulnerabilities", tool, vulns.length());
                        for (int i = 0; i < vulns.length(); i++) {
                            JSONObject vuln = vulns.getJSONObject(i);
                            findings.add(convertMCPToFinding(vuln, tool, location));
                        }
                    } else if (resultObj.has("text")) {
                        String text = resultObj.getString("text");
                        logger.debug("{} result text: {} chars", tool, text.length());
                        logger.debug("{} text preview: {}", tool, text.substring(0, Math.min(500, text.length())));
                        findings.addAll(parseToolOutputText(text, tool, location));
                    } else if (resultObj.has("result")) {
                        // Some tools wrap result in another result object
                        String text = resultObj.getString("result");
                        logger.debug("{} nested result: {} chars", tool, text.length());
                        logger.debug("{} text preview: {}", tool, text.substring(0, Math.min(500, text.length())));
                        findings.addAll(parseToolOutputText(text, tool, location));
                    }
                }
            }
            
        } catch (Exception e) {
            logger.warn("Could not parse {} response: {}", tool, e.getMessage(), e);
        }
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> parseToolOutputText(String output, String tool, String location) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        if (output == null || output.isEmpty()) {
            return findings;
        }
        
        // Parse text output - look for vulnerability indicators
        String[] lines = output.split("\n");
        for (String line : lines) {
            String lowerLine = line.toLowerCase();
            
            // Look for common vulnerability patterns
            if (line.contains("OSVDB") || line.contains("CVE-") || 
                lowerLine.contains("vulnerable") || lowerLine.contains("vulnerability") ||
                lowerLine.contains("critical") || lowerLine.contains("high risk") ||
                lowerLine.contains("open port") && !lowerLine.contains("no open ports") ||
                lowerLine.contains("injection") || lowerLine.contains("xss") ||
                lowerLine.contains("security issue") || lowerLine.contains("outdated") ||
                lowerLine.contains("missing header") || lowerLine.contains("weak") ||
                (lowerLine.contains("found") && lowerLine.contains("directory")) ||
                line.contains("200 OK") || line.contains("301") || line.contains("302")) {
                
                // Skip false positives
                if (!lowerLine.contains("no vulnerabilities") && 
                    !lowerLine.contains("0 vulnerabilities") &&
                    !lowerLine.contains("secure") &&
                    line.trim().length() > 10) {
                    findings.add(createFindingFromText(line, tool, location));
                }
            }
        }
        
        // If output contains significant text but no specific findings, create general finding
        if (findings.isEmpty() && output.length() > 100) {
            logger.debug("{} returned {} chars of output, creating summary finding", tool, output.length());
            findings.add(createFindingFromText("Scan completed - review full output", tool, location));
        }
        
        return findings;
    }
    
    private SecurityAgent.SecurityFinding createFindingFromText(String text, String tool, String location) {
        // Determine severity from keywords
        SecurityAgent.SecurityFinding.Severity severity;
        if (text.toUpperCase().contains("CRITICAL") || text.contains("CVE-")) {
            severity = SecurityAgent.SecurityFinding.Severity.CRITICAL;
        } else if (text.toUpperCase().contains("HIGH") || text.contains("vulnerable")) {
            severity = SecurityAgent.SecurityFinding.Severity.HIGH;
        } else if (text.toUpperCase().contains("MEDIUM")) {
            severity = SecurityAgent.SecurityFinding.Severity.MEDIUM;
        } else {
            severity = SecurityAgent.SecurityFinding.Severity.LOW;
        }
        
        String title = text.length() > 100 ? text.substring(0, 100) + "..." : text;
        
        String fixCode = "// Dynamic Analysis Finding from " + tool + "\n" +
            "// " + text + "\n\n" +
            "// For network-level vulnerabilities, apply fixes at:\n" +
            "// - Application configuration\n" +
            "// - Server/infrastructure level\n" +
            "// - Firewall rules\n" +
            "// - Network segmentation";
        
        return new SecurityAgent.SecurityFinding(
            null,
            null,
            severity,
            tool + ": " + title,
            text,
            location,
            null,
            0.85,
            List.of("Review and remediate based on " + tool + " findings"),
            false,
            "DYNAMIC: MCP-Kali/" + tool,
            fixCode
        );
    }
    
    private SecurityAgent.SecurityFinding convertMCPToFinding(JSONObject vuln, String tool, String location) {
        // Map severity from MCP response
        String severityStr = vuln.optString("severity", "MEDIUM");
        SecurityAgent.SecurityFinding.Severity severity = switch (severityStr.toUpperCase()) {
            case "CRITICAL", "HIGH" -> SecurityAgent.SecurityFinding.Severity.CRITICAL;
            case "MEDIUM" -> SecurityAgent.SecurityFinding.Severity.HIGH;
            case "LOW" -> SecurityAgent.SecurityFinding.Severity.MEDIUM;
            default -> SecurityAgent.SecurityFinding.Severity.LOW;
        };
        
        String title = vuln.optString("title", "Security Issue");
        String description = vuln.optString("description", "Vulnerability detected by " + tool);
        String cve = vuln.optString("cve", null);
        String recommendation = vuln.optString("fix", "Review and remediate the vulnerability");
        
        String fixCode = "// Dynamic Analysis Finding from " + tool + "\n" +
            "// " + recommendation + "\n\n" +
            "// For network-level vulnerabilities, apply fixes at:\n" +
            "// - Application configuration\n" +
            "// - Server/infrastructure level\n" +
            "// - Firewall rules\n" +
            "// - Network segmentation";
        
        return new SecurityAgent.SecurityFinding(
            null,
            null,
            severity,
            tool + ": " + title,
            description,
            location,
            cve,
            0.90, // MCP Kali tools have high confidence
            List.of(recommendation),
            false, // Network vulnerabilities cannot be auto-fixed in code
            "DYNAMIC: MCP-Kali/" + tool,
            fixCode
        );
    }
    
    public void shutdown() {
        if (mcpConnected && mcpGatewayProcess != null) {
            try {
                logger.info("Shutting down MCP Kali Tools connection...");
                
                // Close streams
                if (mcpStdin != null) {
                    mcpStdin.close();
                }
                if (mcpStdout != null) {
                    mcpStdout.close();
                }
                
                // Terminate gateway process
                mcpGatewayProcess.destroy();
                boolean terminated = mcpGatewayProcess.waitFor(5, TimeUnit.SECONDS);
                if (!terminated) {
                    mcpGatewayProcess.destroyForcibly();
                }
                
                mcpConnected = false;
            } catch (Exception e) {
                logger.error("Error shutting down MCP connection", e);
            }
        }
    }
}
