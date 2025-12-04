package com.security.ai.unified;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * NVD (National Vulnerability Database) Client
 * 
 * Provides access to the NVD API (https://nvd.nist.gov/) for:
 * - CVE lookup and details
 * - Vulnerability scoring (CVSS)
 * - CPE matching
 * - Keyword-based vulnerability search
 * 
 * API Documentation: https://nvd.nist.gov/developers/vulnerabilities
 */
public class NVDClient {
    
    private static final Logger logger = LoggerFactory.getLogger(NVDClient.class);
    
    private static final String NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final String NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
    
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private String apiKey; // Optional - increases rate limit from 5 to 50 requests per 30 seconds
    
    // Cache for CVE lookups
    private final Map<String, CVEInfo> cveCache = new ConcurrentHashMap<>();
    private final Map<String, List<CVEInfo>> keywordCache = new ConcurrentHashMap<>();
    
    public NVDClient() {
        this(null);
    }
    
    public NVDClient(String apiKey) {
        this.apiKey = apiKey;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();
        this.objectMapper = new ObjectMapper();
        logger.info("✓ NVD Client initialized" + (apiKey != null ? " (with API key)" : " (no API key - limited rate)"));
    }
    
    /**
     * Look up a specific CVE by ID
     */
    public Optional<CVEInfo> lookupCVE(String cveId) {
        // Check cache first
        if (cveCache.containsKey(cveId)) {
            return Optional.of(cveCache.get(cveId));
        }
        
        try {
            String url = NVD_API_BASE + "?cveId=" + cveId;
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Accept", "application/json");
            
            if (apiKey != null && !apiKey.isEmpty()) {
                requestBuilder.header("apiKey", apiKey);
            }
            
            HttpRequest request = requestBuilder.GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode vulnerabilities = root.path("vulnerabilities");
                
                if (vulnerabilities.isArray() && vulnerabilities.size() > 0) {
                    JsonNode cve = vulnerabilities.get(0).path("cve");
                    CVEInfo cveInfo = parseCVE(cve);
                    cveCache.put(cveId, cveInfo);
                    return Optional.of(cveInfo);
                }
            } else if (response.statusCode() == 403) {
                logger.warn("NVD API rate limit exceeded. Consider adding an API key.");
            }
            
        } catch (Exception e) {
            logger.error("Failed to lookup CVE {}: {}", cveId, e.getMessage());
        }
        
        return Optional.empty();
    }
    
    /**
     * Search for CVEs by keyword
     */
    public List<CVEInfo> searchByKeyword(String keyword, int maxResults) {
        String cacheKey = keyword + ":" + maxResults;
        if (keywordCache.containsKey(cacheKey)) {
            return keywordCache.get(cacheKey);
        }
        
        List<CVEInfo> results = new ArrayList<>();
        
        try {
            String url = NVD_API_BASE + "?keywordSearch=" + keyword.replace(" ", "%20") 
                + "&resultsPerPage=" + Math.min(maxResults, 100);
            
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("Accept", "application/json");
            
            if (apiKey != null && !apiKey.isEmpty()) {
                requestBuilder.header("apiKey", apiKey);
            }
            
            HttpRequest request = requestBuilder.GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode vulnerabilities = root.path("vulnerabilities");
                
                if (vulnerabilities.isArray()) {
                    for (JsonNode vuln : vulnerabilities) {
                        JsonNode cve = vuln.path("cve");
                        results.add(parseCVE(cve));
                    }
                }
                
                keywordCache.put(cacheKey, results);
            }
            
        } catch (Exception e) {
            logger.error("Failed to search NVD for '{}': {}", keyword, e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Search for CVEs affecting a specific CPE (Common Platform Enumeration)
     */
    public List<CVEInfo> searchByCPE(String cpeName, int maxResults) {
        List<CVEInfo> results = new ArrayList<>();
        
        try {
            String url = NVD_API_BASE + "?cpeName=" + cpeName 
                + "&resultsPerPage=" + Math.min(maxResults, 100);
            
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("Accept", "application/json");
            
            if (apiKey != null && !apiKey.isEmpty()) {
                requestBuilder.header("apiKey", apiKey);
            }
            
            HttpRequest request = requestBuilder.GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode vulnerabilities = root.path("vulnerabilities");
                
                if (vulnerabilities.isArray()) {
                    for (JsonNode vuln : vulnerabilities) {
                        JsonNode cve = vuln.path("cve");
                        results.add(parseCVE(cve));
                    }
                }
            }
            
        } catch (Exception e) {
            logger.error("Failed to search NVD by CPE '{}': {}", cpeName, e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Get CVEs by severity level
     */
    public List<CVEInfo> searchBySeverity(String severity, int maxResults) {
        List<CVEInfo> results = new ArrayList<>();
        
        try {
            // Map severity to CVSS v3 ranges
            String severityParam = switch (severity.toUpperCase()) {
                case "CRITICAL" -> "cvssV3Severity=CRITICAL";
                case "HIGH" -> "cvssV3Severity=HIGH";
                case "MEDIUM" -> "cvssV3Severity=MEDIUM";
                case "LOW" -> "cvssV3Severity=LOW";
                default -> "";
            };
            
            if (severityParam.isEmpty()) return results;
            
            String url = NVD_API_BASE + "?" + severityParam + "&resultsPerPage=" + Math.min(maxResults, 100);
            
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("Accept", "application/json");
            
            if (apiKey != null && !apiKey.isEmpty()) {
                requestBuilder.header("apiKey", apiKey);
            }
            
            HttpRequest request = requestBuilder.GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode vulnerabilities = root.path("vulnerabilities");
                
                if (vulnerabilities.isArray()) {
                    for (JsonNode vuln : vulnerabilities) {
                        JsonNode cve = vuln.path("cve");
                        results.add(parseCVE(cve));
                    }
                }
            }
            
        } catch (Exception e) {
            logger.error("Failed to search NVD by severity '{}': {}", severity, e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Get recent CVEs from the last N days
     */
    public List<CVEInfo> getRecentCVEs(int daysBack, int maxResults) {
        List<CVEInfo> results = new ArrayList<>();
        
        try {
            java.time.LocalDateTime now = java.time.LocalDateTime.now();
            java.time.LocalDateTime start = now.minusDays(daysBack);
            
            String startDate = start.format(java.time.format.DateTimeFormatter.ISO_DATE_TIME)
                .replace("T", "T") + "Z";
            String endDate = now.format(java.time.format.DateTimeFormatter.ISO_DATE_TIME)
                .replace("T", "T") + "Z";
            
            String url = NVD_API_BASE + "?pubStartDate=" + startDate + "&pubEndDate=" + endDate
                + "&resultsPerPage=" + Math.min(maxResults, 100);
            
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("Accept", "application/json");
            
            if (apiKey != null && !apiKey.isEmpty()) {
                requestBuilder.header("apiKey", apiKey);
            }
            
            HttpRequest request = requestBuilder.GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode vulnerabilities = root.path("vulnerabilities");
                
                if (vulnerabilities.isArray()) {
                    for (JsonNode vuln : vulnerabilities) {
                        JsonNode cve = vuln.path("cve");
                        results.add(parseCVE(cve));
                    }
                }
            }
            
        } catch (Exception e) {
            logger.error("Failed to get recent CVEs: {}", e.getMessage());
        }
        
        return results;
    }
    
    private CVEInfo parseCVE(JsonNode cve) {
        String id = cve.path("id").asText("");
        String description = "";
        
        // Get English description
        JsonNode descriptions = cve.path("descriptions");
        if (descriptions.isArray()) {
            for (JsonNode desc : descriptions) {
                if ("en".equals(desc.path("lang").asText())) {
                    description = desc.path("value").asText("");
                    break;
                }
            }
        }
        
        // Parse CVSS v3 metrics
        double cvssScore = 0.0;
        String severity = "UNKNOWN";
        String vectorString = "";
        
        JsonNode metrics = cve.path("metrics");
        if (metrics.has("cvssMetricV31") && metrics.path("cvssMetricV31").isArray()) {
            JsonNode cvssV31 = metrics.path("cvssMetricV31").get(0).path("cvssData");
            cvssScore = cvssV31.path("baseScore").asDouble(0.0);
            severity = cvssV31.path("baseSeverity").asText("UNKNOWN");
            vectorString = cvssV31.path("vectorString").asText("");
        } else if (metrics.has("cvssMetricV30") && metrics.path("cvssMetricV30").isArray()) {
            JsonNode cvssV30 = metrics.path("cvssMetricV30").get(0).path("cvssData");
            cvssScore = cvssV30.path("baseScore").asDouble(0.0);
            severity = cvssV30.path("baseSeverity").asText("UNKNOWN");
            vectorString = cvssV30.path("vectorString").asText("");
        }
        
        // Parse weaknesses (CWE)
        List<String> cwes = new ArrayList<>();
        JsonNode weaknesses = cve.path("weaknesses");
        if (weaknesses.isArray()) {
            for (JsonNode weakness : weaknesses) {
                JsonNode descriptions2 = weakness.path("description");
                if (descriptions2.isArray()) {
                    for (JsonNode desc : descriptions2) {
                        String cweId = desc.path("value").asText("");
                        if (cweId.startsWith("CWE-")) {
                            cwes.add(cweId);
                        }
                    }
                }
            }
        }
        
        // Parse references
        List<String> references = new ArrayList<>();
        JsonNode refs = cve.path("references");
        if (refs.isArray()) {
            for (JsonNode ref : refs) {
                references.add(ref.path("url").asText(""));
            }
        }
        
        // Parse published date
        String published = cve.path("published").asText("");
        
        return new CVEInfo(id, description, cvssScore, severity, vectorString, cwes, references, published);
    }
    
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }
    
    public void clearCache() {
        cveCache.clear();
        keywordCache.clear();
    }
    
    /**
     * CVE Information record
     */
    public record CVEInfo(
        String id,
        String description,
        double cvssScore,
        String severity,
        String vectorString,
        List<String> cwes,
        List<String> references,
        String publishedDate
    ) {
        public boolean isCritical() {
            return cvssScore >= 9.0 || "CRITICAL".equalsIgnoreCase(severity);
        }
        
        public boolean isHigh() {
            return cvssScore >= 7.0 || "HIGH".equalsIgnoreCase(severity);
        }
        
        public String getSummary() {
            return String.format("%s (CVSS: %.1f %s) - %s", 
                id, cvssScore, severity, 
                description.length() > 100 ? description.substring(0, 100) + "..." : description);
        }
    }
}
