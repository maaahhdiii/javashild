package com.security.ai.unified;

import com.security.ai.agent.SecurityAgent;
import com.security.ai.analysis.dynamicanalysis.DynamicAnalysisAgent.NetworkRequestInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * OWASP ZAP Native Scanner - Direct ZAP API Integration
 * 
 * Uses OWASP ZAP REST API for comprehensive web application security testing:
 * - Spider: Crawl and discover application structure
 * - Active Scan: Detect vulnerabilities through active testing
 * - Passive Scan: Monitor traffic for security issues
 * - Ajax Spider: JavaScript-heavy application crawling
 */
public class OwaspZapNativeScanner {
    
    private static final Logger logger = LoggerFactory.getLogger(OwaspZapNativeScanner.class);
    
    private ClientApi zapApi;
    private boolean zapConnected = false;
    private String zapApiKey;
    private String zapHost;
    private int zapPort;
    
    public OwaspZapNativeScanner() {
        // Try with empty API key first (ZAP default when API key is disabled)
        this("localhost", 8090, "");
    }
    
    public OwaspZapNativeScanner(String host, int port, String apiKey) {
        this.zapHost = host;
        this.zapPort = port;
        this.zapApiKey = apiKey;
    }
    
    public void initialize() {
        try {
            logger.info("Initializing OWASP ZAP Native Scanner...");
            logger.info("Connecting to ZAP at {}:{}", zapHost, zapPort);
            
            // Initialize ZAP API client (try without API key first, then with default key)
            zapApi = new ClientApi(zapHost, zapPort, zapApiKey);
            
            // Test connection by getting ZAP version
            try {
                ApiResponse version = zapApi.core.version();
                String zapVersion = ((ApiResponseElement) version).getValue();
                logger.info("✓ Connected to OWASP ZAP version: {}", zapVersion);
                zapConnected = true;
                
                // Get scan policies
                ApiResponse policies = zapApi.ascan.scanPolicyNames();
                logger.info("✓ Available scan policies: {}", policies.toString());
                
            } catch (ClientApiException e) {
                // Try with a different approach - maybe API key issue
                logger.warn("API call failed: {} - Trying to fetch existing alerts...", e.getMessage());
                
                // Still mark as connected to try fetching existing alerts
                zapConnected = true;
            }
            
        } catch (Exception e) {
            logger.error("Failed to initialize OWASP ZAP Native Scanner", e);
            zapConnected = false;
        }
    }
    
    public boolean isConnected() {
        return zapConnected;
    }
    
    public List<SecurityAgent.SecurityFinding> scanTarget(NetworkRequestInfo netInfo) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        if (!zapConnected) {
            logger.warn("OWASP ZAP not connected - skipping scan");
            return findings;
        }
        
        try {
            String targetUrl = netInfo.protocol().toLowerCase() + "://" + netInfo.host();
            if (netInfo.port() != 80 && netInfo.port() != 443) {
                targetUrl += ":" + netInfo.port();
            }
            
            logger.info("=== OWASP ZAP scanning: {} ===", targetUrl);
            
            // Try to get existing alerts first (from manual scan)
            try {
                logger.info("[1/4] 🔍 Fetching existing alerts for {}...", targetUrl);
                List<SecurityAgent.SecurityFinding> existingFindings = getExistingAlerts(targetUrl);
                if (!existingFindings.isEmpty()) {
                    logger.info("[1/4] ✓ Found {} existing alerts", existingFindings.size());
                    return existingFindings;
                }
            } catch (Exception e) {
                logger.debug("No existing alerts found: {}", e.getMessage());
            }
            
            // Step 1: Access the URL to add to ZAP context
            logger.info("[1/4] 🌐 Accessing target URL...");
            try {
                zapApi.core.accessUrl(targetUrl, "true");
                Thread.sleep(2000);
                logger.info("[1/4] ✓ Target accessed");
            } catch (ClientApiException e) {
                logger.warn("[1/4] Could not access URL via API: {}", e.getMessage());
                // Try to get alerts anyway
                return getExistingAlerts(targetUrl);
            }
            
            // Step 2: Spider the target
            logger.info("[2/4] 🕷️ Starting Spider scan...");
            ApiResponse spiderResp = zapApi.spider.scan(targetUrl, null, null, null, null);
            String spiderScanId = ((ApiResponseElement) spiderResp).getValue();
            
            // Wait for spider to complete
            int spiderProgress = 0;
            while (spiderProgress < 100) {
                Thread.sleep(1000);
                ApiResponse progressResp = zapApi.spider.status(spiderScanId);
                spiderProgress = Integer.parseInt(((ApiResponseElement) progressResp).getValue());
                if (spiderProgress % 25 == 0) {
                    logger.info("[2/4] Spider progress: {}%", spiderProgress);
                }
            }
            logger.info("[2/4] ✓ Spider scan completed");
            
            // Step 3: Passive scan (runs automatically)
            logger.info("[3/4] 👁️ Running Passive scan...");
            Thread.sleep(2000);
            
            // Wait for passive scan to complete
            int recordsToScan = 1;
            while (recordsToScan > 0) {
                Thread.sleep(500);
                ApiResponse recordsResp = zapApi.pscan.recordsToScan();
                recordsToScan = Integer.parseInt(((ApiResponseElement) recordsResp).getValue());
            }
            logger.info("[3/4] ✓ Passive scan completed");
            
            // Step 4: Active scan
            logger.info("[4/4] ⚡ Starting Active scan...");
            ApiResponse activeScanResp = zapApi.ascan.scan(targetUrl, "True", "False", null, null, null);
            String activeScanId = ((ApiResponseElement) activeScanResp).getValue();
            
            // Wait for active scan to complete
            int activeScanProgress = 0;
            while (activeScanProgress < 100) {
                Thread.sleep(2000);
                ApiResponse progressResp = zapApi.ascan.status(activeScanId);
                activeScanProgress = Integer.parseInt(((ApiResponseElement) progressResp).getValue());
                if (activeScanProgress % 10 == 0 && activeScanProgress > 0) {
                    logger.info("[4/4] Active scan progress: {}%", activeScanProgress);
                }
            }
            logger.info("[4/4] ✓ Active scan completed");
            
            // Step 5: Retrieve alerts
            logger.info("📊 Retrieving scan results...");
            ApiResponse alertsResp = zapApi.core.alerts(targetUrl, null, null);
            
            if (alertsResp instanceof ApiResponseList) {
                ApiResponseList alertsList = (ApiResponseList) alertsResp;
                
                for (ApiResponse alertResp : alertsList.getItems()) {
                    findings.add(parseZapAlert(alertResp, targetUrl));
                }
            }
            
            logger.info("=== OWASP ZAP found {} vulnerabilities in {} ===", findings.size(), targetUrl);
            
        } catch (Exception e) {
            logger.error("OWASP ZAP scan failed for {}: {}", netInfo.host(), e.getMessage(), e);
        }
        
        return findings;
    }
    
    private com.security.ai.agent.SecurityAgent.SecurityFinding parseZapAlert(ApiResponse alertResp, String location) {
        try {
            // ZAP alerts come as ApiResponseSet - extract values using getName/getValue pattern
            String alertName = "Unknown Alert";
            String description = "Security vulnerability detected by OWASP ZAP";
            String risk = "MEDIUM";
            String confidence = "MEDIUM";
            String solution = "";
            String reference = "";
            String cweid = "";
            String url = location;
            
            // ApiResponseSet contains child elements we can iterate
            if (alertResp instanceof ApiResponseSet) {
                ApiResponseSet alertSet = (ApiResponseSet) alertResp;
                
                // Extract each field from the set
                if (alertSet.getAttribute("alert") != null) {
                    alertName = alertSet.getAttribute("alert").toString();
                }
                if (alertSet.getAttribute("name") != null) {
                    alertName = alertSet.getAttribute("name").toString();
                }
                if (alertSet.getAttribute("description") != null) {
                    description = alertSet.getAttribute("description").toString();
                }
                if (alertSet.getAttribute("risk") != null) {
                    risk = alertSet.getAttribute("risk").toString();
                }
                if (alertSet.getAttribute("confidence") != null) {
                    confidence = alertSet.getAttribute("confidence").toString();
                }
                if (alertSet.getAttribute("solution") != null) {
                    solution = alertSet.getAttribute("solution").toString();
                }
                if (alertSet.getAttribute("reference") != null) {
                    reference = alertSet.getAttribute("reference").toString();
                }
                if (alertSet.getAttribute("cweid") != null) {
                    cweid = alertSet.getAttribute("cweid").toString();
                }
                if (alertSet.getAttribute("url") != null) {
                    url = alertSet.getAttribute("url").toString();
                }
            } else {
                // Fallback: use toString but clean it up
                String rawAlert = alertResp.toString();
                if (rawAlert.length() > 100) {
                    alertName = rawAlert.substring(0, 100) + "...";
                } else {
                    alertName = rawAlert;
                }
            }
            
            // Map ZAP risk to severity
            com.security.ai.agent.SecurityAgent.SecurityFinding.Severity severity = switch (risk.toUpperCase()) {
                case "HIGH" -> com.security.ai.agent.SecurityAgent.SecurityFinding.Severity.CRITICAL;
                case "MEDIUM" -> com.security.ai.agent.SecurityAgent.SecurityFinding.Severity.HIGH;
                case "LOW" -> com.security.ai.agent.SecurityAgent.SecurityFinding.Severity.MEDIUM;
                case "INFORMATIONAL", "INFO" -> com.security.ai.agent.SecurityAgent.SecurityFinding.Severity.LOW;
                default -> com.security.ai.agent.SecurityAgent.SecurityFinding.Severity.MEDIUM;
            };
            
            // Map confidence to score
            double confidenceScore = switch (confidence.toUpperCase()) {
                case "HIGH" -> 0.9;
                case "MEDIUM" -> 0.7;
                case "LOW" -> 0.5;
                default -> 0.6;
            };
            
            // Determine category from alert name
            String category = determineCategory(alertName, cweid);
            
            // Build recommendations
            List<String> recommendations = new ArrayList<>();
            if (solution != null && !solution.isEmpty() && !solution.equals("null")) {
                recommendations.add(solution);
            }
            if (reference != null && !reference.isEmpty() && !reference.equals("null")) {
                recommendations.add("Reference: " + reference);
            }
            if (recommendations.isEmpty()) {
                recommendations.add("Review and remediate this vulnerability identified by OWASP ZAP");
            }
            
            // Build CWE ID if available
            String cveId = (cweid != null && !cweid.isEmpty() && !cweid.equals("null") && !cweid.equals("0")) 
                ? "CWE-" + cweid : null;
            
            return new com.security.ai.agent.SecurityAgent.SecurityFinding(
                UUID.randomUUID().toString(),
                Instant.now(),
                severity,
                category,
                alertName + (description != null && !description.equals(alertName) ? " - " + description : ""),
                url,
                cveId,
                confidenceScore,
                recommendations,
                true,
                "DYNAMIC: OWASP-ZAP",
                null
            );
            
        } catch (Exception e) {
            logger.error("Failed to parse ZAP alert: {}", e.getMessage());
            return new com.security.ai.agent.SecurityAgent.SecurityFinding(
                UUID.randomUUID().toString(),
                Instant.now(),
                com.security.ai.agent.SecurityAgent.SecurityFinding.Severity.MEDIUM,
                "Web Application Vulnerability",
                "ZAP Alert: " + alertResp.toString().substring(0, Math.min(200, alertResp.toString().length())),
                location,
                null,
                0.5,
                List.of("Review this vulnerability identified by OWASP ZAP"),
                false,
                "DYNAMIC: OWASP-ZAP",
                null
            );
        }
    }
    
    private String determineCategory(String alertName, String cweid) {
        String lower = alertName.toLowerCase();
        
        if (lower.contains("sql") || lower.contains("injection")) return "SQL_INJECTION";
        if (lower.contains("xss") || lower.contains("cross-site")) return "XSS";
        if (lower.contains("csrf") || lower.contains("cross-site request")) return "CSRF";
        if (lower.contains("xxe") || lower.contains("xml")) return "XXE";
        if (lower.contains("path") || lower.contains("traversal")) return "PATH_TRAVERSAL";
        if (lower.contains("command")) return "COMMAND_INJECTION";
        if (lower.contains("authentication")) return "AUTH_ISSUE";
        if (lower.contains("session")) return "SESSION_MANAGEMENT";
        if (lower.contains("crypto") || lower.contains("encryption")) return "WEAK_CRYPTO";
        if (lower.contains("header") || lower.contains("cors")) return "SECURITY_HEADERS";
        
        return "OWASP_ZAP_FINDING";
    }
    
    /**
     * Fetch existing alerts from ZAP for a given target URL.
     * This is useful when ZAP has already scanned the target manually.
     */
    private List<SecurityAgent.SecurityFinding> getExistingAlerts(String targetUrl) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            // Get all alerts for the base URL
            String baseUrl = targetUrl.replaceAll("/$", ""); // Remove trailing slash
            
            logger.info("Fetching existing ZAP alerts for: {}", baseUrl);
            
            // Try to get alerts - use empty string for baseurl to get all alerts
            ApiResponse alertsResp = zapApi.core.alerts(baseUrl, "0", "100", null);
            
            if (alertsResp instanceof ApiResponseList) {
                ApiResponseList alertList = (ApiResponseList) alertsResp;
                logger.info("Found {} alerts in ZAP", alertList.getItems().size());
                
                for (ApiResponse alertResp : alertList.getItems()) {
                    SecurityAgent.SecurityFinding finding = parseZapAlert(alertResp, targetUrl);
                    findings.add(finding);
                }
            }
            
        } catch (ClientApiException e) {
            logger.warn("Could not fetch existing alerts: {}", e.getMessage());
        }
        
        return findings;
    }
    
    public void shutdown() {
        if (zapConnected) {
            logger.info("Shutting down OWASP ZAP Native Scanner...");
            zapConnected = false;
        }
    }
}
