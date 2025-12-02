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
            
            // Convert to response
            List<FindingDto> findings = result.findings().stream()
                .map(f -> new FindingDto(
                    f.findingId() != null ? f.findingId() : UUID.randomUUID().toString(),
                    f.category(),
                    f.description(),
                    f.severity().name(),
                    f.location(),
                    f.confidenceScore(),
                    f.recommendations()
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
            
            SecurityAgent.SecurityEvent event = new SecurityAgent.SecurityEvent(
                UUID.randomUUID().toString(),
                java.time.Instant.now(),
                SecurityAgent.SecurityEvent.EventType.CODE_CHANGE,
                request.getFilename() != null ? request.getFilename() : "inline-code.java",
                tempFile  // Pass Path object, not String
            );
            
            CompletableFuture<AgentOrchestrator.AggregatedFindings> resultFuture = 
                orchestrator.analyzeEvent(event);
            
            AgentOrchestrator.AggregatedFindings result = resultFuture.get(30, TimeUnit.SECONDS);
            
            List<FindingDto> findings = result.findings().stream()
                .map(f -> new FindingDto(
                    f.findingId() != null ? f.findingId() : UUID.randomUUID().toString(),
                    f.category(),
                    f.description(),
                    f.severity().name(),
                    f.location(),
                    f.confidenceScore(),
                    f.recommendations()
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
            
            List<FindingDto> findings = result.findings().stream()
                .map(f -> new FindingDto(
                    f.findingId() != null ? f.findingId() : UUID.randomUUID().toString(),
                    f.category(),
                    f.description(),
                    f.severity().name(),
                    f.location(),
                    f.confidenceScore(),
                    f.recommendations()
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
            0, // Would track in production
            0,
            Map.of(
                "CRITICAL", 0,
                "HIGH", 0,
                "MEDIUM", 0,
                "LOW", 0
            )
        );
        
        return ResponseEntity.ok(response);
    }
}
