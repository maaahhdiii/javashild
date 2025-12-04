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

/**
 * Client for MISP (Malware Information Sharing Platform) API
 * Provides threat intelligence search and IOC correlation capabilities
 * 
 * MISP is an open source threat intelligence platform for gathering, sharing,
 * storing and correlating Indicators of Compromise (IoCs).
 * 
 * API Documentation: https://www.misp-project.org/openapi/
 */
@Component
public class MispClient {
    
    private static final Logger logger = LoggerFactory.getLogger(MispClient.class);
    
    @Value("${security.misp.url:}")
    private String mispUrl;
    
    @Value("${security.misp.api-key:}")
    private String apiKey;
    
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    
    public MispClient() {
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
        logger.info("MISP Client initialized");
    }
    
    public MispClient(String mispUrl, String apiKey) {
        this();
        this.mispUrl = mispUrl;
        this.apiKey = apiKey;
    }
    
    /**
     * Search for Indicators of Compromise (IOCs)
     * @param query Search term (IP, domain, hash, etc.)
     * @return List of matching IOC records
     */
    public List<Map<String, Object>> searchIOC(String query) {
        logger.info("Searching MISP for IOC: {}", query);
        
        if (!isConfigured()) {
            logger.warn("MISP not configured - returning demo response");
            return generateDemoResponse(query);
        }
        
        try {
            String url = mispUrl + "/attributes/restSearch";
            
            HttpHeaders headers = createHeaders();
            
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("value", query);
            requestBody.put("returnFormat", "json");
            
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                url, HttpMethod.POST, entity, String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return parseAttributeResponse(response.getBody());
            }
            
        } catch (Exception e) {
            logger.error("MISP search failed for {}: {}", query, e.getMessage());
        }
        
        return List.of();
    }
    
    /**
     * Get MISP events by tag
     * @param tag Event tag to search for
     * @return List of matching events
     */
    public List<Map<String, Object>> getEventsByTag(String tag) {
        logger.info("Getting MISP events with tag: {}", tag);
        
        if (!isConfigured()) {
            return List.of();
        }
        
        try {
            String url = mispUrl + "/events/restSearch";
            
            HttpHeaders headers = createHeaders();
            
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("tags", List.of(tag));
            requestBody.put("returnFormat", "json");
            
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                url, HttpMethod.POST, entity, String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return parseEventResponse(response.getBody());
            }
            
        } catch (Exception e) {
            logger.error("MISP event search failed for tag {}: {}", tag, e.getMessage());
        }
        
        return List.of();
    }
    
    /**
     * Get event details by ID
     * @param eventId MISP event ID
     * @return Event details
     */
    public Map<String, Object> getEvent(String eventId) {
        logger.info("Getting MISP event: {}", eventId);
        
        if (!isConfigured()) {
            return Map.of("error", "MISP not configured");
        }
        
        try {
            String url = mispUrl + "/events/view/" + eventId;
            
            HttpHeaders headers = createHeaders();
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                url, HttpMethod.GET, entity, String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                JsonNode root = objectMapper.readTree(response.getBody());
                JsonNode event = root.path("Event");
                
                Map<String, Object> result = new HashMap<>();
                result.put("id", event.path("id").asText());
                result.put("info", event.path("info").asText());
                result.put("date", event.path("date").asText());
                result.put("threatLevel", getThreatLevelName(event.path("threat_level_id").asInt()));
                result.put("analysis", getAnalysisName(event.path("analysis").asInt()));
                result.put("attributeCount", event.path("attribute_count").asInt());
                
                return result;
            }
            
        } catch (Exception e) {
            logger.error("MISP event fetch failed for {}: {}", eventId, e.getMessage());
        }
        
        return Map.of("error", "Event not found");
    }
    
    /**
     * Search for CVE-related indicators
     * @param cveId CVE identifier
     * @return List of IOCs associated with the CVE
     */
    public List<Map<String, Object>> searchCVE(String cveId) {
        logger.info("Searching MISP for CVE: {}", cveId);
        return searchIOC(cveId);
    }
    
    /**
     * Get recent threat intelligence events
     * @param limit Maximum number of events
     * @return List of recent events
     */
    public List<Map<String, Object>> getRecentEvents(int limit) {
        logger.info("Getting {} recent MISP events", limit);
        
        if (!isConfigured()) {
            return List.of();
        }
        
        try {
            String url = mispUrl + "/events/restSearch";
            
            HttpHeaders headers = createHeaders();
            
            Map<String, Object> requestBody = new HashMap<>();
            requestBody.put("limit", limit);
            requestBody.put("returnFormat", "json");
            requestBody.put("published", true);
            
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                url, HttpMethod.POST, entity, String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                return parseEventResponse(response.getBody());
            }
            
        } catch (Exception e) {
            logger.error("MISP recent events fetch failed: {}", e.getMessage());
        }
        
        return List.of();
    }
    
    /**
     * Add a sighting to an attribute (report seeing an IOC)
     * @param attributeId MISP attribute ID
     * @return Success status
     */
    public boolean addSighting(String attributeId) {
        if (!isConfigured()) {
            return false;
        }
        
        try {
            String url = mispUrl + "/sightings/add/" + attributeId;
            
            HttpHeaders headers = createHeaders();
            HttpEntity<String> entity = new HttpEntity<>("{}", headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                url, HttpMethod.POST, entity, String.class
            );
            
            return response.getStatusCode().is2xxSuccessful();
            
        } catch (Exception e) {
            logger.error("Failed to add sighting: {}", e.getMessage());
            return false;
        }
    }
    
    // ================= Helper Methods =================
    
    private HttpHeaders createHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.set("Authorization", apiKey);
        return headers;
    }
    
    private List<Map<String, Object>> parseAttributeResponse(String json) {
        List<Map<String, Object>> results = new ArrayList<>();
        
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode response = root.path("response");
            JsonNode attributes = response.path("Attribute");
            
            if (attributes.isArray()) {
                for (JsonNode attr : attributes) {
                    Map<String, Object> ioc = new HashMap<>();
                    ioc.put("id", attr.path("id").asText());
                    ioc.put("type", attr.path("type").asText());
                    ioc.put("value", attr.path("value").asText());
                    ioc.put("category", attr.path("category").asText());
                    ioc.put("toIds", attr.path("to_ids").asBoolean());
                    ioc.put("timestamp", attr.path("timestamp").asText());
                    ioc.put("comment", attr.path("comment").asText());
                    
                    // Get event info if available
                    if (attr.has("Event")) {
                        JsonNode event = attr.path("Event");
                        ioc.put("eventId", event.path("id").asText());
                        ioc.put("eventInfo", event.path("info").asText());
                        ioc.put("threatLevel", getThreatLevelName(event.path("threat_level_id").asInt()));
                    }
                    
                    results.add(ioc);
                }
            }
            
        } catch (Exception e) {
            logger.error("Failed to parse attribute response: {}", e.getMessage());
        }
        
        return results;
    }
    
    private List<Map<String, Object>> parseEventResponse(String json) {
        List<Map<String, Object>> results = new ArrayList<>();
        
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode response = root.path("response");
            
            if (response.isArray()) {
                for (JsonNode item : response) {
                    JsonNode event = item.path("Event");
                    
                    Map<String, Object> eventData = new HashMap<>();
                    eventData.put("id", event.path("id").asText());
                    eventData.put("info", event.path("info").asText());
                    eventData.put("date", event.path("date").asText());
                    eventData.put("threatLevel", getThreatLevelName(event.path("threat_level_id").asInt()));
                    eventData.put("analysis", getAnalysisName(event.path("analysis").asInt()));
                    eventData.put("published", event.path("published").asBoolean());
                    eventData.put("attributeCount", event.path("attribute_count").asInt());
                    
                    // Get tags
                    List<String> tags = new ArrayList<>();
                    JsonNode tagList = event.path("Tag");
                    if (tagList.isArray()) {
                        for (JsonNode tag : tagList) {
                            tags.add(tag.path("name").asText());
                        }
                    }
                    eventData.put("tags", tags);
                    
                    results.add(eventData);
                }
            }
            
        } catch (Exception e) {
            logger.error("Failed to parse event response: {}", e.getMessage());
        }
        
        return results;
    }
    
    private String getThreatLevelName(int level) {
        return switch (level) {
            case 1 -> "high";
            case 2 -> "medium";
            case 3 -> "low";
            case 4 -> "undefined";
            default -> "unknown";
        };
    }
    
    private String getAnalysisName(int analysis) {
        return switch (analysis) {
            case 0 -> "Initial";
            case 1 -> "Ongoing";
            case 2 -> "Complete";
            default -> "Unknown";
        };
    }
    
    private List<Map<String, Object>> generateDemoResponse(String query) {
        // Return demo data when MISP is not configured
        // This helps demonstrate the UI functionality
        
        List<Map<String, Object>> results = new ArrayList<>();
        
        // Detect IOC type based on query format
        String iocType = detectIOCType(query);
        
        if (iocType != null) {
            Map<String, Object> demo = new HashMap<>();
            demo.put("type", iocType);
            demo.put("value", query);
            demo.put("threatLevel", "medium");
            demo.put("category", "Network activity");
            demo.put("comment", "Demo result - Configure MISP for real threat intelligence");
            demo.put("eventInfo", "Demo Event - MISP Integration Test");
            demo.put("toIds", false);
            results.add(demo);
        }
        
        return results;
    }
    
    private String detectIOCType(String query) {
        if (query == null || query.isBlank()) {
            return null;
        }
        
        // IP address
        if (query.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) {
            return "ip-dst";
        }
        
        // Domain
        if (query.matches("[a-zA-Z0-9][a-zA-Z0-9-]*\\.[a-zA-Z]{2,}.*")) {
            return "domain";
        }
        
        // MD5 hash
        if (query.matches("[a-fA-F0-9]{32}")) {
            return "md5";
        }
        
        // SHA1 hash
        if (query.matches("[a-fA-F0-9]{40}")) {
            return "sha1";
        }
        
        // SHA256 hash
        if (query.matches("[a-fA-F0-9]{64}")) {
            return "sha256";
        }
        
        // URL
        if (query.toLowerCase().startsWith("http://") || query.toLowerCase().startsWith("https://")) {
            return "url";
        }
        
        // Email
        if (query.contains("@") && query.contains(".")) {
            return "email";
        }
        
        // CVE
        if (query.toUpperCase().startsWith("CVE-")) {
            return "vulnerability";
        }
        
        return "text";
    }
    
    /**
     * Check if MISP is configured
     */
    public boolean isConfigured() {
        return mispUrl != null && !mispUrl.isBlank() 
            && apiKey != null && !apiKey.isBlank();
    }
    
    /**
     * Set MISP URL programmatically
     */
    public void setMispUrl(String url) {
        this.mispUrl = url;
    }
    
    /**
     * Set API key programmatically
     */
    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }
    
    /**
     * Get MISP server info
     */
    public Map<String, Object> getServerInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("configured", isConfigured());
        info.put("url", mispUrl != null ? mispUrl : "Not configured");
        info.put("hasApiKey", apiKey != null && !apiKey.isBlank());
        return info;
    }
}
