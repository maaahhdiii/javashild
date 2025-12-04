package com.security.ai.web.controller;

import com.security.ai.agent.SecurityAgent;
import com.security.ai.unified.UnifiedMLSecurityAgent;
import com.security.ai.web.dto.AnalysisResultResponse;
import com.security.ai.web.dto.FindingDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * External Monitoring API Controller
 * 
 * REST endpoints for external applications to submit code, logs, and runtime events
 * for security analysis. This allows other servers/applications to use JavaShield
 * as a centralized security monitoring service.
 * 
 * Endpoints:
 * - POST /api/monitor/code - Analyze code from external source
 * - POST /api/monitor/runtime - Analyze runtime events
 * - POST /api/monitor/logs - Analyze application logs
 * - GET /api/monitor/findings/{sessionId} - Get findings for session
 * - POST /api/monitor/subscribe - Subscribe to real-time alerts
 */
@RestController
@RequestMapping("/api/monitor")
@CrossOrigin(origins = "*")
public class ExternalMonitoringController {
    
    private static final Logger logger = LoggerFactory.getLogger(ExternalMonitoringController.class);
    
    private final UnifiedMLSecurityAgent unifiedAgent;
    private final Map<String, List<SecurityAgent.SecurityFinding>> sessionFindings = new HashMap<>();
    
    public ExternalMonitoringController(UnifiedMLSecurityAgent unifiedAgent) {
        this.unifiedAgent = unifiedAgent;
        logger.info("External Monitoring API initialized - Ready to accept remote analysis requests");
    }
    
    /**
     * Analyze code submitted from external application
     * 
     * POST /api/monitor/code
     * Body: {
     *   "sessionId": "unique-session-id",
     *   "applicationName": "MyApp",
     *   "sourceCode": "public class Test { ... }",
     *   "language": "java"
     * }
     */
    @PostMapping("/code")
    public ResponseEntity<AnalysisResultResponse> analyzeExternalCode(@RequestBody ExternalCodeRequest request) {
        try {
            logger.info("External code analysis request from: {} (session: {})", 
                request.applicationName(), request.sessionId());
            
            // Save code to temp file
            Path tempFile = Files.createTempFile("external-code-", ".java");
            Files.writeString(tempFile, request.sourceCode());
            
            // Analyze using unified agent
            SecurityAgent.SecurityEvent event = new SecurityAgent.SecurityEvent(
                null, null,
                SecurityAgent.SecurityEvent.EventType.CODE_CHANGE,
                request.applicationName(),
                tempFile
            );
            
            List<SecurityAgent.SecurityFinding> findings = unifiedAgent.performAnalysis(event);
            
            // Store findings for session
            sessionFindings.put(request.sessionId(), findings);
            
            // Clean up temp file
            Files.deleteIfExists(tempFile);
            
            // Convert to response
            return ResponseEntity.ok(buildResponse(findings, request.sourceCode()));
            
        } catch (Exception e) {
            logger.error("External code analysis failed", e);
            return ResponseEntity.status(500)
                .body(new AnalysisResultResponse("error", List.of(), 0, 0, 0, null));
        }
    }
    
    /**
     * Analyze runtime events from external application
     * 
     * POST /api/monitor/runtime
     * Body: {
     *   "sessionId": "unique-session-id",
     *   "applicationName": "MyApp",
     *   "eventType": "NETWORK_REQUEST",
     *   "eventData": {
     *     "protocol": "HTTP",
     *     "host": "example.com",
     *     "port": 80
     *   }
     * }
     */
    @PostMapping("/runtime")
    public ResponseEntity<AnalysisResultResponse> analyzeRuntimeEvent(@RequestBody ExternalRuntimeRequest request) {
        try {
            logger.info("External runtime analysis request from: {} (type: {})", 
                request.applicationName(), request.eventType());
            
            // Create appropriate event based on type
            SecurityAgent.SecurityEvent event = createRuntimeEvent(request);
            
            // Analyze using unified agent
            List<SecurityAgent.SecurityFinding> findings = unifiedAgent.performAnalysis(event);
            
            // Store findings for session
            sessionFindings.computeIfAbsent(request.sessionId(), k -> new ArrayList<>()).addAll(findings);
            
            return ResponseEntity.ok(buildResponse(findings, null));
            
        } catch (Exception e) {
            logger.error("External runtime analysis failed", e);
            return ResponseEntity.status(500)
                .body(new AnalysisResultResponse("error", List.of(), 0, 0, 0, null));
        }
    }
    
    /**
     * Analyze application logs from external application
     * 
     * POST /api/monitor/logs
     * Body: {
     *   "sessionId": "unique-session-id",
     *   "applicationName": "MyApp",
     *   "logLevel": "ERROR",
     *   "logMessage": "SQL Exception: ...",
     *   "stackTrace": "..."
     * }
     */
    @PostMapping("/logs")
    public ResponseEntity<AnalysisResultResponse> analyzeApplicationLogs(@RequestBody ExternalLogRequest request) {
        try {
            logger.info("External log analysis request from: {} (level: {})", 
                request.applicationName(), request.logLevel());
            
            // Analyze logs for security patterns
            List<SecurityAgent.SecurityFinding> findings = analyzeLogsForPatterns(request);
            
            // Store findings for session
            sessionFindings.computeIfAbsent(request.sessionId(), k -> new ArrayList<>()).addAll(findings);
            
            return ResponseEntity.ok(buildResponse(findings, null));
            
        } catch (Exception e) {
            logger.error("External log analysis failed", e);
            return ResponseEntity.status(500)
                .body(new AnalysisResultResponse("error", List.of(), 0, 0, 0, null));
        }
    }
    
    /**
     * Get all findings for a session
     * 
     * GET /api/monitor/findings/{sessionId}
     */
    @GetMapping("/findings/{sessionId}")
    public ResponseEntity<AnalysisResultResponse> getSessionFindings(@PathVariable String sessionId) {
        List<SecurityAgent.SecurityFinding> findings = sessionFindings.getOrDefault(sessionId, List.of());
        return ResponseEntity.ok(buildResponse(findings, null));
    }
    
    /**
     * Subscribe to real-time alerts (WebSocket endpoint would be better)
     * 
     * POST /api/monitor/subscribe
     * Body: {
     *   "sessionId": "unique-session-id",
     *   "webhookUrl": "https://myapp.com/security-alerts",
     *   "severityFilter": ["CRITICAL", "HIGH"]
     * }
     */
    @PostMapping("/subscribe")
    public ResponseEntity<Map<String, String>> subscribeToAlerts(@RequestBody SubscriptionRequest request) {
        logger.info("Alert subscription request for session: {}", request.sessionId());
        
        // TODO: Implement webhook mechanism to send alerts to external application
        
        return ResponseEntity.ok(Map.of(
            "status", "subscribed",
            "sessionId", request.sessionId(),
            "message", "Will send alerts to: " + request.webhookUrl()
        ));
    }
    
    /**
     * Health check endpoint
     * 
     * GET /api/monitor/health
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        return ResponseEntity.ok(Map.of(
            "status", "healthy",
            "agent", "unified-ml-security-agent",
            "statistics", unifiedAgent.getStatistics()
        ));
    }
    
    // Helper methods
    
    private SecurityAgent.SecurityEvent createRuntimeEvent(ExternalRuntimeRequest request) {
        // TODO: Create proper event based on eventType and eventData
        return new SecurityAgent.SecurityEvent(
            null, null,
            SecurityAgent.SecurityEvent.EventType.valueOf(request.eventType()),
            request.applicationName(),
            request.eventData()
        );
    }
    
    private List<SecurityAgent.SecurityFinding> analyzeLogsForPatterns(ExternalLogRequest request) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        String logMessage = request.logMessage().toLowerCase();
        
        // SQL exception patterns
        if (logMessage.contains("sql") && logMessage.contains("syntax")) {
            findings.add(new SecurityAgent.SecurityFinding(
                null, null,
                SecurityAgent.SecurityFinding.Severity.HIGH,
                "Potential SQL Injection",
                "SQL syntax error in logs suggests possible SQL injection attempt",
                request.applicationName() + " logs",
                "CWE-89",
                0.70,
                List.of("Review SQL query construction"),
                false
            ));
        }
        
        // Authentication failure patterns
        if (logMessage.contains("authentication failed") || logMessage.contains("access denied")) {
            findings.add(new SecurityAgent.SecurityFinding(
                null, null,
                SecurityAgent.SecurityFinding.Severity.MEDIUM,
                "Authentication Failure",
                "Multiple authentication failures detected",
                request.applicationName() + " logs",
                "CWE-287",
                0.60,
                List.of("Implement rate limiting", "Monitor for brute force attacks"),
                false
            ));
        }
        
        return findings;
    }
    
    private AnalysisResultResponse buildResponse(List<SecurityAgent.SecurityFinding> findings, String code) {
        List<FindingDto> findingDtos = findings.stream()
            .map(this::convertToFindingDto)
            .collect(Collectors.toList());
        
        int criticalCount = (int) findings.stream()
            .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL)
            .count();
        
        int highCount = (int) findings.stream()
            .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH)
            .count();
        
        return new AnalysisResultResponse(
            "success",
            findingDtos,
            findings.size(),
            criticalCount,
            highCount,
            code
        );
    }
    
    private FindingDto convertToFindingDto(SecurityAgent.SecurityFinding finding) {
        return new FindingDto(
            finding.findingId(),
            finding.category(),
            finding.description(),
            finding.severity().name(),
            finding.location(),
            finding.confidenceScore(),
            finding.recommendations(),
            finding.autoRemediationPossible(),
            finding.detectionSource(),
            finding.fixCode()
        );
    }
    
    // Request DTOs
    
    public record ExternalCodeRequest(
        String sessionId,
        String applicationName,
        String sourceCode,
        String language
    ) {}
    
    public record ExternalRuntimeRequest(
        String sessionId,
        String applicationName,
        String eventType,
        Map<String, Object> eventData
    ) {}
    
    public record ExternalLogRequest(
        String sessionId,
        String applicationName,
        String logLevel,
        String logMessage,
        String stackTrace
    ) {}
    
    public record SubscriptionRequest(
        String sessionId,
        String webhookUrl,
        List<String> severityFilter
    ) {}
}
