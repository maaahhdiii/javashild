package com.security.ai.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;

/**
 * JavaShield Monitoring Client SDK
 * 
 * Embed this client in your Java application to automatically send
 * code, runtime events, and logs to JavaShield for security analysis.
 * 
 * Usage:
 * <pre>
 * JavaShieldClient client = new JavaShieldClient.Builder()
 *     .serverUrl("http://javashield-server:8080")
 *     .applicationName("MyApp")
 *     .autoMonitoring(true)
 *     .build();
 * 
 * // Analyze code
 * AnalysisResult result = client.analyzeCode(sourceCode);
 * 
 * // Send runtime event
 * client.reportNetworkRequest("HTTP", "example.com", 80);
 * 
 * // Subscribe to alerts
 * client.subscribeToAlerts("https://myapp.com/webhook", List.of("CRITICAL", "HIGH"));
 * </pre>
 */
public class JavaShieldClient implements AutoCloseable {
    
    private static final Logger logger = LoggerFactory.getLogger(JavaShieldClient.class);
    
    private final String serverUrl;
    private final String applicationName;
    private final String sessionId;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ExecutorService executor;
    private final BlockingQueue<MonitoringEvent> eventQueue;
    private final boolean autoMonitoring;
    
    private volatile boolean running = false;
    
    private JavaShieldClient(Builder builder) {
        this.serverUrl = builder.serverUrl;
        this.applicationName = builder.applicationName;
        this.sessionId = builder.sessionId != null ? builder.sessionId : UUID.randomUUID().toString();
        this.autoMonitoring = builder.autoMonitoring;
        
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
        
        this.objectMapper = new ObjectMapper();
        this.executor = Executors.newVirtualThreadPerTaskExecutor();
        this.eventQueue = new LinkedBlockingQueue<>(1000);
        
        if (autoMonitoring) {
            startMonitoring();
        }
        
        logger.info("JavaShield Client initialized - Server: {}, App: {}, Session: {}", 
            serverUrl, applicationName, sessionId);
    }
    
    /**
     * Analyze source code for vulnerabilities
     */
    public AnalysisResult analyzeCode(String sourceCode) {
        return analyzeCode(sourceCode, "java");
    }
    
    /**
     * Analyze source code for vulnerabilities
     */
    public AnalysisResult analyzeCode(String sourceCode, String language) {
        try {
            Map<String, Object> request = Map.of(
                "sessionId", sessionId,
                "applicationName", applicationName,
                "sourceCode", sourceCode,
                "language", language
            );
            
            String requestBody = objectMapper.writeValueAsString(request);
            
            HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/monitor/code"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
            
            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                return objectMapper.readValue(response.body(), AnalysisResult.class);
            } else {
                logger.error("Code analysis failed with status: {}", response.statusCode());
                return new AnalysisResult("error", List.of(), 0, 0, 0);
            }
            
        } catch (Exception e) {
            logger.error("Failed to analyze code", e);
            return new AnalysisResult("error", List.of(), 0, 0, 0);
        }
    }
    
    /**
     * Report network request for runtime analysis
     */
    public void reportNetworkRequest(String protocol, String host, int port) {
        Map<String, Object> eventData = Map.of(
            "protocol", protocol,
            "host", host,
            "port", port
        );
        
        queueRuntimeEvent("NETWORK_REQUEST", eventData);
    }
    
    /**
     * Report file access for runtime analysis
     */
    public void reportFileAccess(String path, String operation) {
        Map<String, Object> eventData = Map.of(
            "path", path,
            "operation", operation
        );
        
        queueRuntimeEvent("FILE_ACCESS", eventData);
    }
    
    /**
     * Report API call for runtime analysis
     */
    public void reportAPICall(String className, String methodName) {
        Map<String, Object> eventData = Map.of(
            "className", className,
            "methodName", methodName
        );
        
        queueRuntimeEvent("API_CALL", eventData);
    }
    
    /**
     * Report application log for analysis
     */
    public void reportLog(String logLevel, String logMessage, String stackTrace) {
        try {
            Map<String, Object> request = Map.of(
                "sessionId", sessionId,
                "applicationName", applicationName,
                "logLevel", logLevel,
                "logMessage", logMessage,
                "stackTrace", stackTrace != null ? stackTrace : ""
            );
            
            String requestBody = objectMapper.writeValueAsString(request);
            
            HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/monitor/logs"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
            
            // Send asynchronously
            executor.submit(() -> {
                try {
                    httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
                } catch (Exception e) {
                    logger.error("Failed to report log", e);
                }
            });
            
        } catch (Exception e) {
            logger.error("Failed to report log", e);
        }
    }
    
    /**
     * Get all findings for current session
     */
    public AnalysisResult getFindings() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/monitor/findings/" + sessionId))
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 200) {
                return objectMapper.readValue(response.body(), AnalysisResult.class);
            } else {
                logger.error("Get findings failed with status: {}", response.statusCode());
                return new AnalysisResult("error", List.of(), 0, 0, 0);
            }
            
        } catch (Exception e) {
            logger.error("Failed to get findings", e);
            return new AnalysisResult("error", List.of(), 0, 0, 0);
        }
    }
    
    /**
     * Subscribe to real-time security alerts via webhook
     */
    public boolean subscribeToAlerts(String webhookUrl, List<String> severityFilter) {
        try {
            Map<String, Object> request = Map.of(
                "sessionId", sessionId,
                "webhookUrl", webhookUrl,
                "severityFilter", severityFilter
            );
            
            String requestBody = objectMapper.writeValueAsString(request);
            
            HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/monitor/subscribe"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
            
            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            
            logger.info("Alert subscription status: {}", response.statusCode());
            return response.statusCode() == 200;
            
        } catch (Exception e) {
            logger.error("Failed to subscribe to alerts", e);
            return false;
        }
    }
    
    /**
     * Check JavaShield server health
     */
    public boolean isServerHealthy() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/monitor/health"))
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
            
        } catch (Exception e) {
            logger.error("Health check failed", e);
            return false;
        }
    }
    
    // Internal methods
    
    private void queueRuntimeEvent(String eventType, Map<String, Object> eventData) {
        try {
            eventQueue.offer(new MonitoringEvent(eventType, eventData), 1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            logger.warn("Failed to queue runtime event", e);
            Thread.currentThread().interrupt();
        }
    }
    
    private void startMonitoring() {
        running = true;
        
        executor.submit(() -> {
            logger.info("Auto-monitoring started");
            
            while (running) {
                try {
                    MonitoringEvent event = eventQueue.poll(1, TimeUnit.SECONDS);
                    if (event != null) {
                        sendRuntimeEvent(event);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error in monitoring loop", e);
                }
            }
            
            logger.info("Auto-monitoring stopped");
        });
    }
    
    private void sendRuntimeEvent(MonitoringEvent event) {
        try {
            Map<String, Object> request = Map.of(
                "sessionId", sessionId,
                "applicationName", applicationName,
                "eventType", event.eventType(),
                "eventData", event.eventData()
            );
            
            String requestBody = objectMapper.writeValueAsString(request);
            
            HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(serverUrl + "/api/monitor/runtime"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
            
            httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            
        } catch (Exception e) {
            logger.error("Failed to send runtime event", e);
        }
    }
    
    @Override
    public void close() {
        running = false;
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        logger.info("JavaShield Client closed");
    }
    
    // Builder pattern
    
    public static class Builder {
        private String serverUrl = "http://localhost:8080";
        private String applicationName = "UnknownApp";
        private String sessionId;
        private boolean autoMonitoring = false;
        
        public Builder serverUrl(String serverUrl) {
            this.serverUrl = serverUrl;
            return this;
        }
        
        public Builder applicationName(String applicationName) {
            this.applicationName = applicationName;
            return this;
        }
        
        public Builder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }
        
        public Builder autoMonitoring(boolean autoMonitoring) {
            this.autoMonitoring = autoMonitoring;
            return this;
        }
        
        public JavaShieldClient build() {
            return new JavaShieldClient(this);
        }
    }
    
    // DTOs
    
    public record AnalysisResult(
        String status,
        List<Finding> findings,
        int totalFindings,
        int criticalCount,
        int highCount
    ) {}
    
    public record Finding(
        String id,
        String category,
        String description,
        String severity,
        String location,
        double confidence,
        List<String> recommendations,
        boolean autoFixAvailable
    ) {}
    
    private record MonitoringEvent(String eventType, Map<String, Object> eventData) {}
}
