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
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * MISP (Malware Information Sharing Platform) Client
 * 
 * Provides access to MISP threat intelligence feeds (https://www.misp-project.org/):
 * - Threat indicators (IOCs)
 * - Malware signatures
 * - Attack patterns
 * - Threat actor information
 * - STIX/TAXII integration
 * 
 * API Documentation: https://www.misp-project.org/openapi/
 */
public class MISPClient {
    
    private static final Logger logger = LoggerFactory.getLogger(MISPClient.class);
    
    private final String mispUrl;
    private final String apiKey;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    // Cache for threat indicators
    private final Map<String, ThreatIndicator> indicatorCache = new ConcurrentHashMap<>();
    private final Map<String, List<ThreatEvent>> eventCache = new ConcurrentHashMap<>();
    
    // Default public MISP instances (for demo/testing)
    public static final String CIRCL_MISP = "https://misppriv.circl.lu";
    public static final String BOTVRIJ_MISP = "https://misp.botvrij.eu";
    
    public MISPClient(String mispUrl, String apiKey) {
        this.mispUrl = mispUrl.endsWith("/") ? mispUrl.substring(0, mispUrl.length() - 1) : mispUrl;
        this.apiKey = apiKey;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();
        this.objectMapper = new ObjectMapper();
        logger.info("✓ MISP Client initialized for: {}", mispUrl);
    }
    
    /**
     * Search for threat events containing specific attributes
     */
    public List<ThreatEvent> searchEvents(String searchTerm, int limit) {
        String cacheKey = searchTerm + ":" + limit;
        if (eventCache.containsKey(cacheKey)) {
            return eventCache.get(cacheKey);
        }
        
        List<ThreatEvent> events = new ArrayList<>();
        
        try {
            String url = mispUrl + "/events/restSearch";
            String requestBody = objectMapper.writeValueAsString(Map.of(
                "returnFormat", "json",
                "limit", limit,
                "value", searchTerm,
                "enforceWarninglist", true
            ));
            
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("Authorization", apiKey)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode responseNode = root.path("response");
                
                if (responseNode.isArray()) {
                    for (JsonNode eventNode : responseNode) {
                        events.add(parseEvent(eventNode.path("Event")));
                    }
                }
                
                eventCache.put(cacheKey, events);
                logger.debug("Found {} MISP events for '{}'", events.size(), searchTerm);
            }
            
        } catch (Exception e) {
            logger.error("Failed to search MISP events: {}", e.getMessage());
        }
        
        return events;
    }
    
    /**
     * Get threat indicators (IOCs) by type
     */
    public List<ThreatIndicator> getIndicatorsByType(IndicatorType type, int limit) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        
        try {
            String url = mispUrl + "/attributes/restSearch";
            String requestBody = objectMapper.writeValueAsString(Map.of(
                "returnFormat", "json",
                "limit", limit,
                "type", type.getMispType(),
                "to_ids", true
            ));
            
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("Authorization", apiKey)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode attributes = root.path("response").path("Attribute");
                
                if (attributes.isArray()) {
                    for (JsonNode attr : attributes) {
                        indicators.add(parseAttribute(attr));
                    }
                }
                
                logger.debug("Found {} MISP indicators of type {}", indicators.size(), type);
            }
            
        } catch (Exception e) {
            logger.error("Failed to get MISP indicators: {}", e.getMessage());
        }
        
        return indicators;
    }
    
    /**
     * Check if a value matches any known threat indicators
     */
    public Optional<ThreatIndicator> checkIndicator(String value, IndicatorType type) {
        String cacheKey = type + ":" + value;
        if (indicatorCache.containsKey(cacheKey)) {
            return Optional.of(indicatorCache.get(cacheKey));
        }
        
        try {
            String url = mispUrl + "/attributes/restSearch";
            String requestBody = objectMapper.writeValueAsString(Map.of(
                "returnFormat", "json",
                "value", value,
                "type", type.getMispType()
            ));
            
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", apiKey)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode attributes = root.path("response").path("Attribute");
                
                if (attributes.isArray() && attributes.size() > 0) {
                    ThreatIndicator indicator = parseAttribute(attributes.get(0));
                    indicatorCache.put(cacheKey, indicator);
                    return Optional.of(indicator);
                }
            }
            
        } catch (Exception e) {
            logger.debug("MISP check failed for {}: {}", value, e.getMessage());
        }
        
        return Optional.empty();
    }
    
    /**
     * Get recent threat events from the last N days
     */
    public List<ThreatEvent> getRecentEvents(int daysBack, int limit) {
        List<ThreatEvent> events = new ArrayList<>();
        
        try {
            String url = mispUrl + "/events/restSearch";
            String requestBody = objectMapper.writeValueAsString(Map.of(
                "returnFormat", "json",
                "limit", limit,
                "last", daysBack + "d",
                "enforceWarninglist", true
            ));
            
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("Authorization", apiKey)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode responseNode = root.path("response");
                
                if (responseNode.isArray()) {
                    for (JsonNode eventNode : responseNode) {
                        events.add(parseEvent(eventNode.path("Event")));
                    }
                }
                
                logger.info("Retrieved {} recent MISP events from last {} days", events.size(), daysBack);
            }
            
        } catch (Exception e) {
            logger.error("Failed to get recent MISP events: {}", e.getMessage());
        }
        
        return events;
    }
    
    /**
     * Get threat galaxies (attack patterns, threat actors, etc.)
     */
    public List<ThreatGalaxy> getGalaxies() {
        List<ThreatGalaxy> galaxies = new ArrayList<>();
        
        try {
            String url = mispUrl + "/galaxies";
            
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", apiKey)
                .header("Accept", "application/json")
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                
                if (root.isArray()) {
                    for (JsonNode galaxyNode : root) {
                        JsonNode galaxy = galaxyNode.path("Galaxy");
                        galaxies.add(new ThreatGalaxy(
                            galaxy.path("id").asText(""),
                            galaxy.path("name").asText(""),
                            galaxy.path("type").asText(""),
                            galaxy.path("description").asText(""),
                            galaxy.path("namespace").asText("")
                        ));
                    }
                }
            }
            
        } catch (Exception e) {
            logger.error("Failed to get MISP galaxies: {}", e.getMessage());
        }
        
        return galaxies;
    }
    
    /**
     * Search for MITRE ATT&CK patterns
     */
    public List<AttackPattern> searchAttackPatterns(String technique) {
        List<AttackPattern> patterns = new ArrayList<>();
        
        try {
            String url = mispUrl + "/galaxy_clusters/restSearch";
            String requestBody = objectMapper.writeValueAsString(Map.of(
                "returnFormat", "json",
                "value", technique,
                "galaxy_id", "mitre-attack-pattern"
            ));
            
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", apiKey)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode clusters = root.path("response");
                
                if (clusters.isArray()) {
                    for (JsonNode cluster : clusters) {
                        patterns.add(new AttackPattern(
                            cluster.path("value").asText(""),
                            cluster.path("description").asText(""),
                            cluster.path("meta").path("external_id").asText(""),
                            parseTactics(cluster.path("meta").path("kill_chain"))
                        ));
                    }
                }
            }
            
        } catch (Exception e) {
            logger.error("Failed to search attack patterns: {}", e.getMessage());
        }
        
        return patterns;
    }
    
    private ThreatEvent parseEvent(JsonNode event) {
        List<ThreatIndicator> indicators = new ArrayList<>();
        JsonNode attributes = event.path("Attribute");
        if (attributes.isArray()) {
            for (JsonNode attr : attributes) {
                indicators.add(parseAttribute(attr));
            }
        }
        
        List<String> tags = new ArrayList<>();
        JsonNode tagsNode = event.path("Tag");
        if (tagsNode.isArray()) {
            for (JsonNode tag : tagsNode) {
                tags.add(tag.path("name").asText(""));
            }
        }
        
        return new ThreatEvent(
            event.path("id").asText(""),
            event.path("info").asText(""),
            event.path("threat_level_id").asText(""),
            event.path("analysis").asText(""),
            event.path("date").asText(""),
            indicators,
            tags
        );
    }
    
    private ThreatIndicator parseAttribute(JsonNode attr) {
        return new ThreatIndicator(
            attr.path("id").asText(""),
            attr.path("type").asText(""),
            attr.path("value").asText(""),
            attr.path("category").asText(""),
            attr.path("to_ids").asBoolean(false),
            attr.path("comment").asText(""),
            Instant.ofEpochSecond(attr.path("timestamp").asLong(0))
        );
    }
    
    private List<String> parseTactics(JsonNode killChain) {
        List<String> tactics = new ArrayList<>();
        if (killChain.isArray()) {
            for (JsonNode kc : killChain) {
                String[] parts = kc.asText("").split(":");
                if (parts.length > 1) {
                    tactics.add(parts[1]);
                }
            }
        }
        return tactics;
    }
    
    public void clearCache() {
        indicatorCache.clear();
        eventCache.clear();
    }
    
    /**
     * Indicator types supported by MISP
     */
    public enum IndicatorType {
        IP_ADDRESS("ip-dst"),
        IP_SOURCE("ip-src"),
        DOMAIN("domain"),
        URL("url"),
        EMAIL("email-src"),
        FILE_HASH_MD5("md5"),
        FILE_HASH_SHA1("sha1"),
        FILE_HASH_SHA256("sha256"),
        FILENAME("filename"),
        REGISTRY_KEY("regkey"),
        VULNERABILITY("vulnerability"),
        MALWARE_SAMPLE("malware-sample");
        
        private final String mispType;
        
        IndicatorType(String mispType) {
            this.mispType = mispType;
        }
        
        public String getMispType() {
            return mispType;
        }
    }
    
    /**
     * Threat Event record
     */
    public record ThreatEvent(
        String id,
        String info,
        String threatLevel,
        String analysis,
        String date,
        List<ThreatIndicator> indicators,
        List<String> tags
    ) {
        public String getThreatLevelName() {
            return switch (threatLevel) {
                case "1" -> "HIGH";
                case "2" -> "MEDIUM";
                case "3" -> "LOW";
                case "4" -> "UNDEFINED";
                default -> "UNKNOWN";
            };
        }
    }
    
    /**
     * Threat Indicator (IOC) record
     */
    public record ThreatIndicator(
        String id,
        String type,
        String value,
        String category,
        boolean toIds,
        String comment,
        Instant timestamp
    ) {}
    
    /**
     * Threat Galaxy record
     */
    public record ThreatGalaxy(
        String id,
        String name,
        String type,
        String description,
        String namespace
    ) {}
    
    /**
     * MITRE ATT&CK Pattern record
     */
    public record AttackPattern(
        String name,
        String description,
        String mitreId,
        List<String> tactics
    ) {}
}
