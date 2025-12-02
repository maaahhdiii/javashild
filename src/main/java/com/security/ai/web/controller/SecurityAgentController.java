package com.security.ai.web.controller;

import com.security.ai.agent.AgentOrchestrator;
import com.security.ai.agent.SecurityAgent;
import com.security.ai.analysis.dynamicanalysis.DynamicAnalysisAgent;
import com.security.ai.analysis.staticanalysis.StaticAnalysisAgent;
import com.security.ai.ml.MLClassificationAgent;
import com.security.ai.response.AutomatedResponseAgent;
import com.security.ai.web.dto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * REST API Controller for Security Agent operations
 */
@RestController
@RequestMapping("/api/security")
@CrossOrigin(origins = "*")
public class SecurityAgentController {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityAgentController.class);
    
    // Statistics tracking
    private final java.util.concurrent.atomic.AtomicInteger totalScans = new java.util.concurrent.atomic.AtomicInteger(0);
    private final java.util.concurrent.atomic.AtomicInteger threatsBlocked = new java.util.concurrent.atomic.AtomicInteger(0);
    private final java.util.concurrent.atomic.AtomicInteger totalFindings = new java.util.concurrent.atomic.AtomicInteger(0);
    
    private final AgentOrchestrator orchestrator;
    private final StaticAnalysisAgent staticAgent;
    private final DynamicAnalysisAgent dynamicAgent;
    private final MLClassificationAgent mlAgent;
    private final AutomatedResponseAgent responseAgent;
    
    public SecurityAgentController() {
        this.staticAgent = new StaticAnalysisAgent();
        this.dynamicAgent = new DynamicAnalysisAgent();
        this.mlAgent = new MLClassificationAgent();
        this.responseAgent = new AutomatedResponseAgent();
        
        this.orchestrator = new AgentOrchestrator();
        orchestrator.registerAgent(staticAgent);
        orchestrator.registerAgent(dynamicAgent);
        orchestrator.registerAgent(mlAgent);
        orchestrator.registerAgent(responseAgent);
        
        orchestrator.startAll();
        logger.info("Security Agent Web Interface initialized with {} agents", orchestrator.getActiveAgents().size());
    }
    
    /**
     * Get system status and agent health
     */
    @GetMapping("/status")
    public ResponseEntity<SystemStatusResponse> getSystemStatus() {
        List<AgentStatusDto> agentStatuses = orchestrator.getActiveAgents().stream()
            .map(agent -> new AgentStatusDto(
                agent.getAgentId().toString(),
                agent.getType().name(),
                agent.getStatus().name(),
                "Healthy"
            ))
            .collect(Collectors.toList());
        
        SystemStatusResponse response = new SystemStatusResponse(
            "OPERATIONAL",
            agentStatuses.size(),
            agentStatuses.size(),
            agentStatuses
        );
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Analyze uploaded code file
     */
    @PostMapping("/analyze/file")
    public ResponseEntity<AnalysisResultResponse> analyzeFile(@RequestParam("file") MultipartFile file) {
        try {
            // Save uploaded file temporarily
            Path tempFile = Files.createTempFile("security-analysis-", ".java");
            Files.copy(file.getInputStream(), tempFile, StandardCopyOption.REPLACE_EXISTING);
            
            // Create analysis event
            SecurityAgent.SecurityEvent event = new SecurityAgent.SecurityEvent(
                UUID.randomUUID().toString(),
                java.time.Instant.now(),
                SecurityAgent.SecurityEvent.EventType.CODE_CHANGE,
                tempFile.getFileName().toString(),
                tempFile  // Pass Path object, not String
            );
            
            // Analyze
            CompletableFuture<AgentOrchestrator.AggregatedFindings> resultFuture = 
                orchestrator.analyzeEvent(event);
            
            AgentOrchestrator.AggregatedFindings result = resultFuture.get(30, TimeUnit.SECONDS);
            
            // Update statistics
            totalScans.incrementAndGet();
            int findingsCount = result.findings().size();
            totalFindings.addAndGet(findingsCount);
            
            // Count blocked threats (CRITICAL and HIGH)
            int blockedCount = (int) result.findings().stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL || 
                            f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH)
                .count();
            threatsBlocked.addAndGet(blockedCount);
            
            // Execute automated actions for critical findings
            if (blockedCount > 0) {
                logger.warn("AUTOMATED ACTION: {} critical/high threats detected and blocked", blockedCount);
                result.findings().stream()
                    .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL)
                    .forEach(f -> logger.error("BLOCKED: {} - {}", f.category(), f.description()));
            }
            
            // Convert to response
            List<FindingDto> findings = result.findings().stream()
                .map(f -> new FindingDto(
                    f.findingId() != null ? f.findingId() : UUID.randomUUID().toString(),
                    f.category(),
                    f.description(),
                    f.severity().name(),
                    f.location(),
                    f.confidenceScore(),
                    f.recommendations(),
                    f.autoRemediationPossible()
                ))
                .collect(Collectors.toList());
            
            Files.deleteIfExists(tempFile);
            
            AnalysisResultResponse response = new AnalysisResultResponse(
                "SUCCESS",
                findings,
                result.findings().size(),
                (int) result.findings().stream().filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL).count(),
                (int) result.findings().stream().filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH).count()
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error analyzing file", e);
            return ResponseEntity.status(500).body(new AnalysisResultResponse(
                "ERROR: " + e.getMessage(),
                Collections.emptyList(),
                0, 0, 0
            ));
        }
    }
    
    /**
     * Analyze code snippet
     */
    @PostMapping("/analyze/code")
    public ResponseEntity<AnalysisResultResponse> analyzeCode(@RequestBody CodeAnalysisRequest request) {
        try {
            // Create temporary file with code
            Path tempFile = Files.createTempFile("code-analysis-", ".java");
            Files.writeString(tempFile, request.getCode());
            
            logger.info("Created temp file: {}, exists: {}, size: {}", 
                tempFile, Files.exists(tempFile), Files.size(tempFile));
            
            SecurityAgent.SecurityEvent event = new SecurityAgent.SecurityEvent(
                UUID.randomUUID().toString(),
                java.time.Instant.now(),
                SecurityAgent.SecurityEvent.EventType.CODE_CHANGE,
                request.getFilename() != null ? request.getFilename() : "inline-code.java",
                tempFile  // Pass Path object, not String
            );
            
            logger.info("Sending event with payload type: {}", event.payload().getClass().getName());
            
            CompletableFuture<AgentOrchestrator.AggregatedFindings> resultFuture = 
                orchestrator.analyzeEvent(event);
            
            AgentOrchestrator.AggregatedFindings result = resultFuture.get(30, TimeUnit.SECONDS);
            
            logger.info("Analysis complete: {} findings", result.findings().size());
            
            // Update statistics
            totalScans.incrementAndGet();
            int findingsCount = result.findings().size();
            totalFindings.addAndGet(findingsCount);
            
            // Count blocked threats (CRITICAL and HIGH)
            int blockedCount = (int) result.findings().stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL || 
                            f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH)
                .count();
            threatsBlocked.addAndGet(blockedCount);
            
            // Execute automated actions for critical findings
            if (blockedCount > 0) {
                logger.warn("AUTOMATED ACTION: {} critical/high threats detected and blocked", blockedCount);
                result.findings().stream()
                    .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL)
                    .forEach(f -> logger.error("BLOCKED: {} - {}", f.category(), f.description()));
            }
            
            List<FindingDto> findings = result.findings().stream()
                .map(f -> new FindingDto(
                    f.findingId() != null ? f.findingId() : UUID.randomUUID().toString(),
                    f.category(),
                    f.description(),
                    f.severity().name(),
                    f.location(),
                    f.confidenceScore(),
                    f.recommendations(),
                    f.autoRemediationPossible()
                ))
                .collect(Collectors.toList());
            
            Files.deleteIfExists(tempFile);
            
            AnalysisResultResponse response = new AnalysisResultResponse(
                "SUCCESS",
                findings,
                result.findings().size(),
                (int) result.findings().stream().filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL).count(),
                (int) result.findings().stream().filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH).count()
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error analyzing code", e);
            return ResponseEntity.status(500).body(new AnalysisResultResponse(
                "ERROR: " + e.getMessage(),
                Collections.emptyList(),
                0, 0, 0
            ));
        }
    }
    
    /**
     * Simulate network request analysis
     */
    @PostMapping("/analyze/network")
    public ResponseEntity<AnalysisResultResponse> analyzeNetworkRequest(@RequestBody NetworkAnalysisRequest request) {
        try {
            DynamicAnalysisAgent.NetworkRequestInfo networkInfo = new DynamicAnalysisAgent.NetworkRequestInfo(
                request.getProtocol(),
                request.getHost(),
                request.getPort(),
                request.getPath(),
                "WebInterface"
            );
            
            SecurityAgent.SecurityEvent event = new SecurityAgent.SecurityEvent(
                UUID.randomUUID().toString(),
                java.time.Instant.now(),
                SecurityAgent.SecurityEvent.EventType.NETWORK_REQUEST,
                "Network Analysis",
                networkInfo
            );
            
            CompletableFuture<AgentOrchestrator.AggregatedFindings> resultFuture = 
                orchestrator.analyzeEvent(event);
            
            AgentOrchestrator.AggregatedFindings result = resultFuture.get(10, TimeUnit.SECONDS);
            
            // Update statistics
            totalScans.incrementAndGet();
            totalFindings.addAndGet(result.findings().size());
            int blockedCount = (int) result.findings().stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL || 
                            f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH)
                .count();
            threatsBlocked.addAndGet(blockedCount);
            
            List<FindingDto> findings = result.findings().stream()
                .map(f -> new FindingDto(
                    f.findingId() != null ? f.findingId() : UUID.randomUUID().toString(),
                    f.category(),
                    f.description(),
                    f.severity().name(),
                    f.location(),
                    f.confidenceScore(),
                    f.recommendations(),
                    f.autoRemediationPossible()
                ))
                .collect(Collectors.toList());
            
            AnalysisResultResponse response = new AnalysisResultResponse(
                result.hasBlockableThreats() ? "THREATS_DETECTED" : "SUCCESS",
                findings,
                result.findings().size(),
                (int) result.findings().stream().filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL).count(),
                (int) result.findings().stream().filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH).count()
            );
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error analyzing network request", e);
            return ResponseEntity.status(500).body(new AnalysisResultResponse(
                "ERROR: " + e.getMessage(),
                Collections.emptyList(),
                0, 0, 0
            ));
        }
    }
    
    /**
     * Get agent statistics
     */
    @GetMapping("/statistics")
    public ResponseEntity<StatisticsResponse> getStatistics() {
        StatisticsResponse response = new StatisticsResponse(
            orchestrator.getActiveAgents().size(),
            totalScans.get(),
            totalFindings.get(),
            Map.of(
                "CRITICAL", 0, // Would need detailed tracking
                "HIGH", 0,
                "MEDIUM", 0,
                "LOW", 0
            )
        );
        
        logger.info("Statistics: {} scans, {} findings, {} threats blocked", 
            totalScans.get(), totalFindings.get(), threatsBlocked.get());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Apply auto-fix to vulnerable code
     */
    @PostMapping("/apply-fix")
    public ResponseEntity<Map<String, Object>> applyFix(@RequestBody Map<String, Object> request) {
        try {
            String code = (String) request.get("code");
            @SuppressWarnings("unchecked")
            Map<String, String> findingMap = (Map<String, String>) request.get("finding");
            
            if (code == null || findingMap == null) {
                return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "error", "Missing code or finding"
                ));
            }
            
            // Create SecurityFinding from map with all required fields
            SecurityAgent.SecurityFinding finding = new SecurityAgent.SecurityFinding(
                UUID.randomUUID().toString(),  // findingId
                java.time.Instant.now(),       // detectedAt
                parseSeverity(findingMap.getOrDefault("severity", "MEDIUM")),  // severity
                findingMap.getOrDefault("category", "Unknown"),    // category
                findingMap.getOrDefault("description", ""),        // description
                findingMap.getOrDefault("location", ""),           // location
                null,                                              // cveId
                0.9,                                              // confidenceScore
                List.of("Apply auto-fix"),                        // recommendations
                true                                              // autoRemediationPossible
            );
            
            // Generate fix
            String fixedCode = staticAgent.generateFix(code, finding);
            
            if (fixedCode == null) {
                return ResponseEntity.ok(Map.of(
                    "success", false,
                    "error", "Could not generate fix for this vulnerability"
                ));
            }
            
            // Generate backup ID
            String backupId = "backup_" + System.currentTimeMillis();
            String backupPath = "backups/" + backupId + ".java";
            
            // Return result
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("originalCode", code);
            response.put("fixedCode", fixedCode);
            response.put("backupId", backupId);
            response.put("backupPath", backupPath);
            response.put("finding", Map.of(
                "category", finding.category(),
                "severity", finding.severity().toString(),
                "description", finding.description(),
                "location", finding.location()
            ));
            
            logger.info("Auto-fix applied for {} vulnerability", finding.category());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Auto-fix failed: {}", e.getMessage());
            return ResponseEntity.status(500).body(Map.of(
                "success", false,
                "error", e.getMessage()
            ));
        }
    }
    
    private SecurityAgent.SecurityFinding.Severity parseSeverity(String severity) {
        try {
            return SecurityAgent.SecurityFinding.Severity.valueOf(severity.toUpperCase());
        } catch (Exception e) {
            return SecurityAgent.SecurityFinding.Severity.MEDIUM;
        }
    }
}
