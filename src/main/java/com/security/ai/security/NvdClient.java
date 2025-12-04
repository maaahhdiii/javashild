package com.security.ai.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Client for NIST National Vulnerability Database (NVD) API
 * Provides CVE lookup and vulnerability search capabilities
 * 
 * API Documentation: https://nvd.nist.gov/developers/vulnerabilities
 */
@Component
public class NvdClient {
    
    private static final Logger logger = LoggerFactory.getLogger(NvdClient.class);
    
    private static final String NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    
    @Value("${security.nvd.api-key:}")
    private String apiKey;
    
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    
    // Rate limiting: NVD allows 5 requests per 30 seconds without API key
    private long lastRequestTime = 0;
    private static final long RATE_LIMIT_MS = 6000; // 6 seconds between requests
    
    public NvdClient() {
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
        logger.info("NVD Client initialized");
    }
    
    /**
     * Lookup a specific CVE by ID
     * @param cveId CVE identifier (e.g., CVE-2021-44228)
     * @return Map containing CVE details
     */
    public Map<String, Object> lookupCVE(String cveId) {
        logger.info("Looking up CVE: {}", cveId);
        
        // Validate CVE ID format
        if (!isValidCveId(cveId)) {
            return Map.of(
                "error", "Invalid CVE ID format. Expected: CVE-YYYY-NNNNN",
                "cveId", cveId
            );
        }
        
        try {
            // Rate limiting
            enforceRateLimit();
            
            String url = NVD_API_BASE + "?cveId=" + cveId;
            
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            if (apiKey != null && !apiKey.isBlank()) {
                headers.set("apiKey", apiKey);
            }
            
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                url, HttpMethod.GET, entity, String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return parseCveResponse(response.getBody(), cveId);
            } else {
                return Map.of(
                    "cveId", cveId,
                    "error", "NVD API returned status: " + response.getStatusCode(),
                    "nvdUrl", "https://nvd.nist.gov/vuln/detail/" + cveId
                );
            }
            
        } catch (Exception e) {
            logger.error("CVE lookup failed for {}: {}", cveId, e.getMessage());
            return Map.of(
                "cveId", cveId,
                "error", "Lookup failed: " + e.getMessage(),
                "nvdUrl", "https://nvd.nist.gov/vuln/detail/" + cveId
            );
        }
    }
    
    /**
     * Search for CVEs by keyword
     * @param keyword Search term
     * @param maxResults Maximum results to return
     * @return List of matching CVEs
     */
    public List<Map<String, Object>> searchCVEs(String keyword, int maxResults) {
        logger.info("Searching CVEs for keyword: {}", keyword);
        
        try {
            enforceRateLimit();
            
            String url = NVD_API_BASE + "?keywordSearch=" + keyword + "&resultsPerPage=" + Math.min(maxResults, 50);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            if (apiKey != null && !apiKey.isBlank()) {
                headers.set("apiKey", apiKey);
            }
            
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                url, HttpMethod.GET, entity, String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return parseSearchResponse(response.getBody());
            }
            
        } catch (Exception e) {
            logger.error("CVE search failed for {}: {}", keyword, e.getMessage());
        }
        
        return List.of();
    }
    
    /**
     * Get CVEs by CWE ID
     * @param cweId CWE identifier (e.g., CWE-79 for XSS)
     * @return List of CVEs associated with the CWE
     */
    public List<Map<String, Object>> getCVEsByCWE(String cweId) {
        logger.info("Getting CVEs for CWE: {}", cweId);
        
        try {
            enforceRateLimit();
            
            String url = NVD_API_BASE + "?cweId=" + cweId + "&resultsPerPage=20";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            if (apiKey != null && !apiKey.isBlank()) {
                headers.set("apiKey", apiKey);
            }
            
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                url, HttpMethod.GET, entity, String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return parseSearchResponse(response.getBody());
            }
            
        } catch (Exception e) {
            logger.error("CWE CVE lookup failed for {}: {}", cweId, e.getMessage());
        }
        
        return List.of();
    }
    
    /**
     * Get recent CVEs within a date range
     * @param days Number of days to look back
     * @return List of recent CVEs
     */
    public List<Map<String, Object>> getRecentCVEs(int days) {
        logger.info("Getting CVEs from last {} days", days);
        
        try {
            enforceRateLimit();
            
            LocalDateTime endDate = LocalDateTime.now();
            LocalDateTime startDate = endDate.minusDays(days);
            
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");
            
            String url = NVD_API_BASE + 
                "?pubStartDate=" + startDate.format(formatter) + 
                "&pubEndDate=" + endDate.format(formatter) +
                "&resultsPerPage=20";
            
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            if (apiKey != null && !apiKey.isBlank()) {
                headers.set("apiKey", apiKey);
            }
            
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                url, HttpMethod.GET, entity, String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return parseSearchResponse(response.getBody());
            }
            
        } catch (Exception e) {
            logger.error("Recent CVE lookup failed: {}", e.getMessage());
        }
        
        return List.of();
    }
    
    // ================= Helper Methods =================
    
    private boolean isValidCveId(String cveId) {
        if (cveId == null) return false;
        // CVE-YYYY-NNNNN format
        return cveId.toUpperCase().matches("CVE-\\d{4}-\\d{4,}");
    }
    
    private void enforceRateLimit() {
        long now = System.currentTimeMillis();
        long elapsed = now - lastRequestTime;
        if (elapsed < RATE_LIMIT_MS) {
            try {
                Thread.sleep(RATE_LIMIT_MS - elapsed);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        lastRequestTime = System.currentTimeMillis();
    }
    
    private Map<String, Object> parseCveResponse(String json, String cveId) {
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode vulnerabilities = root.path("vulnerabilities");
            
            if (vulnerabilities.isArray() && vulnerabilities.size() > 0) {
                JsonNode cve = vulnerabilities.get(0).path("cve");
                
                Map<String, Object> result = new HashMap<>();
                result.put("cveId", cve.path("id").asText(cveId));
                
                // Get description
                JsonNode descriptions = cve.path("descriptions");
                if (descriptions.isArray()) {
                    for (JsonNode desc : descriptions) {
                        if ("en".equals(desc.path("lang").asText())) {
                            result.put("description", desc.path("value").asText());
                            break;
                        }
                    }
                }
                
                // Get CVSS score and severity
                JsonNode metrics = cve.path("metrics");
                if (metrics.has("cvssMetricV31")) {
                    JsonNode cvss31 = metrics.path("cvssMetricV31").get(0);
                    JsonNode cvssData = cvss31.path("cvssData");
                    result.put("cvssScore", cvssData.path("baseScore").asDouble());
                    result.put("severity", cvssData.path("baseSeverity").asText());
                    result.put("attackVector", cvssData.path("attackVector").asText());
                    result.put("attackComplexity", cvssData.path("attackComplexity").asText());
                } else if (metrics.has("cvssMetricV2")) {
                    JsonNode cvss2 = metrics.path("cvssMetricV2").get(0);
                    result.put("cvssScore", cvss2.path("cvssData").path("baseScore").asDouble());
                    result.put("severity", cvss2.path("baseSeverity").asText());
                }
                
                // Get published date
                result.put("publishedDate", cve.path("published").asText());
                result.put("lastModified", cve.path("lastModified").asText());
                
                // Get CWE IDs
                JsonNode weaknesses = cve.path("weaknesses");
                List<String> cweIds = new ArrayList<>();
                if (weaknesses.isArray()) {
                    for (JsonNode weakness : weaknesses) {
                        JsonNode wDesc = weakness.path("description");
                        if (wDesc.isArray()) {
                            for (JsonNode d : wDesc) {
                                cweIds.add(d.path("value").asText());
                            }
                        }
                    }
                }
                result.put("cweIds", cweIds);
                
                // Get references
                JsonNode references = cve.path("references");
                List<String> refs = new ArrayList<>();
                if (references.isArray()) {
                    for (JsonNode ref : references) {
                        refs.add(ref.path("url").asText());
                    }
                }
                result.put("references", refs.size() > 5 ? refs.subList(0, 5) : refs);
                
                result.put("nvdUrl", "https://nvd.nist.gov/vuln/detail/" + cveId);
                
                return result;
            }
            
            return Map.of(
                "cveId", cveId,
                "error", "CVE not found in NVD",
                "nvdUrl", "https://nvd.nist.gov/vuln/detail/" + cveId
            );
            
        } catch (Exception e) {
            logger.error("Failed to parse CVE response: {}", e.getMessage());
            return Map.of(
                "cveId", cveId,
                "error", "Failed to parse response: " + e.getMessage(),
                "nvdUrl", "https://nvd.nist.gov/vuln/detail/" + cveId
            );
        }
    }
    
    private List<Map<String, Object>> parseSearchResponse(String json) {
        List<Map<String, Object>> results = new ArrayList<>();
        
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode vulnerabilities = root.path("vulnerabilities");
            
            if (vulnerabilities.isArray()) {
                for (JsonNode vuln : vulnerabilities) {
                    JsonNode cve = vuln.path("cve");
                    
                    Map<String, Object> entry = new HashMap<>();
                    String cveId = cve.path("id").asText();
                    entry.put("cveId", cveId);
                    
                    // Get English description
                    JsonNode descriptions = cve.path("descriptions");
                    if (descriptions.isArray()) {
                        for (JsonNode desc : descriptions) {
                            if ("en".equals(desc.path("lang").asText())) {
                                String text = desc.path("value").asText();
                                // Truncate long descriptions
                                if (text.length() > 200) {
                                    text = text.substring(0, 200) + "...";
                                }
                                entry.put("description", text);
                                break;
                            }
                        }
                    }
                    
                    // Get severity
                    JsonNode metrics = cve.path("metrics");
                    if (metrics.has("cvssMetricV31")) {
                        JsonNode cvss = metrics.path("cvssMetricV31").get(0).path("cvssData");
                        entry.put("cvssScore", cvss.path("baseScore").asDouble());
                        entry.put("severity", cvss.path("baseSeverity").asText());
                    } else if (metrics.has("cvssMetricV2")) {
                        JsonNode cvss = metrics.path("cvssMetricV2").get(0);
                        entry.put("cvssScore", cvss.path("cvssData").path("baseScore").asDouble());
                        entry.put("severity", cvss.path("baseSeverity").asText());
                    } else {
                        entry.put("severity", "UNKNOWN");
                    }
                    
                    entry.put("publishedDate", cve.path("published").asText());
                    entry.put("nvdUrl", "https://nvd.nist.gov/vuln/detail/" + cveId);
                    
                    results.add(entry);
                }
            }
            
        } catch (Exception e) {
            logger.error("Failed to parse search response: {}", e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Set API key programmatically
     */
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }
    
    /**
     * Check if API key is configured
     */
    public boolean isApiKeyConfigured() {
        return apiKey != null && !apiKey.isBlank();
    }
}
