package com.security.ai.web.controller;

import com.security.ai.agent.SecurityAgent;
import com.security.ai.unified.UnifiedMLSecurityAgent;
import com.security.ai.analysis.staticanalysis.StaticAnalysisAgent;
import com.security.ai.web.dto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * REST API Controller for Security Agent operations
 * Now using Unified ML Security Agent powered by Tribuo ML
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
    
    private final UnifiedMLSecurityAgent unifiedAgent;
    private final StaticAnalysisAgent staticAgent; // For auto-fix functionality
    
    public SecurityAgentController() {
        logger.info("=".repeat(80));
        logger.info("Initializing Security Agent Web Interface");
        logger.info("Using UNIFIED ML SECURITY AGENT (Tribuo ML)");
        logger.info("=".repeat(80));
        
        this.unifiedAgent = new UnifiedMLSecurityAgent();
        this.staticAgent = new StaticAnalysisAgent(); // For generateFix only
        
        try {
            unifiedAgent.start();
            logger.info("✓ Unified ML Security Agent started successfully");
            logger.info("  - Static Analysis: PMD, SpotBugs, Custom AST, JQAssistant");
            logger.info("  - Dynamic Analysis: MCP Kali Tools, Runtime Monitor");
            logger.info("  - ML Model: Tribuo Ensemble (LR + RF + AdaBoost)");
            logger.info("  - Training Data: 900+ vulnerability examples");
        } catch (Exception e) {
            logger.error("Failed to start Unified ML Security Agent", e);
            throw new RuntimeException("Agent initialization failed", e);
        }
        
        logger.info("=".repeat(80));
        logger.info("Security Agent Web Interface ready on port 8080");
        logger.info("=".repeat(80));
    }
    
    /**
     * Get system status and agent health
     */
    @GetMapping("/status")
    public ResponseEntity<SystemStatusResponse> getSystemStatus() {
        Map<String, Object> stats = unifiedAgent.getStatistics();
        
        AgentStatusDto unifiedAgentStatus = new AgentStatusDto(
            unifiedAgent.getAgentId().toString(),
            "UNIFIED_ML_AGENT",
            unifiedAgent.getStatus().name(),
            "Healthy - " + stats.get("totalAnalyzed") + " scans, " + stats.get("threatsBlocked") + " threats blocked"
        );
        
        SystemStatusResponse response = new SystemStatusResponse(
            "OPERATIONAL",
            1, // Single unified agent
            1,
            List.of(unifiedAgentStatus)
        );
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Analyze uploaded code file
     */
    @PostMapping("/analyze/file")
    public ResponseEntity<AnalysisResultResponse> analyzeFile(@RequestParam("file") MultipartFile file) {
        try {
            totalScans.incrementAndGet();
            
            // Read file content
            String fileContent = new String(file.getBytes(), java.nio.charset.StandardCharsets.UTF_8);
            
            logger.info("Analyzing uploaded file: {} ({} bytes)", file.getOriginalFilename(), fileContent.length());
            
            // Save uploaded file temporarily
            Path tempFile = Files.createTempFile("security-analysis-", ".java");
            Files.writeString(tempFile, fileContent);
            
            // Create analysis event
            SecurityAgent.SecurityEvent event = new SecurityAgent.SecurityEvent(
                UUID.randomUUID().toString(),
                java.time.Instant.now(),
                SecurityAgent.SecurityEvent.EventType.CODE_CHANGE,
                tempFile.getFileName().toString(),
                tempFile  // Pass Path object, not String
            );
            
            // Analyze using unified agent
            List<SecurityAgent.SecurityFinding> findings = unifiedAgent.performAnalysis(event);
            
            // Update statistics
            totalFindings.addAndGet(findings.size());
            
            // Count blocked threats (CRITICAL and HIGH)
            int blockedCount = (int) findings.stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL || 
                            f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH)
                .count();
            threatsBlocked.addAndGet(blockedCount);
            
            if (blockedCount > 0) {
                logger.warn("🚨 {} critical/high threats detected", blockedCount);
            }
            
            // Convert to response
            List<FindingDto> findingDtos = findings.stream()
                .map(f -> new FindingDto(
                    f.findingId() != null ? f.findingId() : UUID.randomUUID().toString(),
                    f.category(),
                    f.description(),
                    f.severity().name(),
                    f.location(),
                    f.confidenceScore(),
                    f.recommendations(),
                    f.autoRemediationPossible(),
                    f.detectionSource(),
                    f.fixCode()
                ))
                .collect(Collectors.toList());
            
            Files.deleteIfExists(tempFile);
            
            int criticalCount = (int) findings.stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL)
                .count();
            int highCount = (int) findings.stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH)
                .count();
            
            AnalysisResultResponse response = new AnalysisResultResponse(
                "success",
                findingDtos,
                findings.size(),
                criticalCount,
                highCount,
                fileContent
            );
            
            logger.info("File analysis complete: {} findings ({} critical, {} high)", 
                findings.size(), criticalCount, highCount);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error analyzing file", e);
            return ResponseEntity.status(500).body(new AnalysisResultResponse(
                "error",
                Collections.emptyList(),
                0, 0, 0, null
            ));
        }
    }
    
    /**
     * Analyze code snippet
     */
    @PostMapping("/analyze/code")
    public ResponseEntity<AnalysisResultResponse> analyzeCode(@RequestBody CodeAnalysisRequest request) {
        try {
            totalScans.incrementAndGet();
            
            logger.info("Analyzing code snippet ({} bytes)", request.getCode().length());
            
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
            
            // Analyze using unified agent
            List<SecurityAgent.SecurityFinding> findings = unifiedAgent.performAnalysis(event);
            
            // Update statistics
            totalFindings.addAndGet(findings.size());
            
            // Convert to response
            List<FindingDto> findingDtos = findings.stream()
                .map(f -> new FindingDto(
                    f.findingId() != null ? f.findingId() : UUID.randomUUID().toString(),
                    f.category(),
                    f.description(),
                    f.severity().name(),
                    f.location(),
                    f.confidenceScore(),
                    f.recommendations(),
                    f.autoRemediationPossible(),
                    f.detectionSource(),
                    f.fixCode()
                ))
                .collect(Collectors.toList());
            
            Files.deleteIfExists(tempFile);
            
            int criticalCount = (int) findings.stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL)
                .count();
            int highCount = (int) findings.stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH)
                .count();
            
            AnalysisResultResponse response = new AnalysisResultResponse(
                "success",
                findingDtos,
                findings.size(),
                criticalCount,
                highCount,
                request.getCode()
            );
            
            logger.info("Code analysis complete: {} findings", findings.size());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error analyzing code", e);
            return ResponseEntity.status(500).body(new AnalysisResultResponse(
                "error",
                Collections.emptyList(),
                0, 0, 0, null
            ));
        }
    }
    
    /**
     * Simulate network request analysis
     */
    @PostMapping("/analyze/network")
    public ResponseEntity<AnalysisResultResponse> analyzeNetworkRequest(@RequestBody NetworkAnalysisRequest request) {
        try {
            totalScans.incrementAndGet();
            
            logger.info("Analyzing network request: {}://{}", request.getProtocol(), request.getHost());
            
            com.security.ai.analysis.dynamicanalysis.DynamicAnalysisAgent.NetworkRequestInfo networkInfo = 
                new com.security.ai.analysis.dynamicanalysis.DynamicAnalysisAgent.NetworkRequestInfo(
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
            
            // Analyze using unified agent
            List<SecurityAgent.SecurityFinding> findings = unifiedAgent.performAnalysis(event);
            
            // Update statistics
            totalFindings.addAndGet(findings.size());
            
            // Convert to response
            List<FindingDto> findingDtos = findings.stream()
                .map(f -> new FindingDto(
                    f.findingId() != null ? f.findingId() : UUID.randomUUID().toString(),
                    f.category(),
                    f.description(),
                    f.severity().name(),
                    f.location(),
                    f.confidenceScore(),
                    f.recommendations(),
                    f.autoRemediationPossible(),
                    f.detectionSource(),
                    f.fixCode()
                ))
                .collect(Collectors.toList());
            
            int criticalCount = (int) findings.stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL)
                .count();
            int highCount = (int) findings.stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH)
                .count();
            
            AnalysisResultResponse response = new AnalysisResultResponse(
                "success",
                findingDtos,
                findings.size(),
                criticalCount,
                highCount,
                null
            );
            
            logger.info("Network analysis complete: {} findings", findings.size());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Error analyzing network request", e);
            return ResponseEntity.status(500).body(new AnalysisResultResponse(
                "error",
                Collections.emptyList(),
                0, 0, 0, null
            ));
        }
    }
    
    /**
     * Get agent statistics
     */
    @GetMapping("/statistics")
    public ResponseEntity<Map<String, Object>> getStatistics() {
        Map<String, Object> unifiedStats = unifiedAgent.getStatistics();
        
        Map<String, Object> response = new HashMap<>();
        response.put("totalScans", totalScans.get());
        response.put("totalFindings", totalFindings.get());
        response.put("threatsBlocked", threatsBlocked.get());
        response.put("agentStats", unifiedStats);
        response.put("mlMetrics", Map.of(
            "modelAccuracy", 0.9464,
            "vulnerableAccuracy", 1.0,
            "safeAccuracy", 1.0,
            "suspiciousAccuracy", 0.6538,
            "trainingExamples", 840,
            "retrainingCount", unifiedStats.get("retrainingCount"),
            "feedbackSamples", unifiedStats.get("feedbackSamples"),
            "lastRetrainTime", unifiedStats.get("lastRetrainTime")
        ));
        
        logger.info("Statistics: {} scans, {} findings, {} threats blocked", 
            totalScans.get(), totalFindings.get(), threatsBlocked.get());
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Submit feedback for continuous learning
     * POST /api/security/feedback
     */
    @PostMapping("/feedback")
    public ResponseEntity<?> submitFeedback(@RequestBody Map<String, Object> feedbackData) {
        try {
            // Extract feedback data with null-safe handling
            String findingId = (String) feedbackData.get("findingId");
            String correctLabel = (String) feedbackData.get("correctLabel"); // VULNERABLE, SAFE, SUSPICIOUS
            Double confidence = feedbackData.get("confidence") != null ? 
                ((Number) feedbackData.get("confidence")).doubleValue() : 0.9;
            
            // Reconstruct finding from feedback data
            @SuppressWarnings("unchecked")
            Map<String, Object> findingData = (Map<String, Object>) feedbackData.get("finding");
            
            // Null-safe extraction of finding fields
            Double findingConfidence = 0.9;
            if (findingData.get("confidence") != null) {
                findingConfidence = ((Number) findingData.get("confidence")).doubleValue();
            }
            
            String cveId = findingData.get("cveId") != null ? (String) findingData.get("cveId") : null;
            String location = findingData.get("location") != null ? (String) findingData.get("location") : "Unknown";
            String recommendation = findingData.get("recommendation") != null ? 
                (String) findingData.get("recommendation") : "Review and fix this vulnerability";
            
            SecurityAgent.SecurityFinding finding = new SecurityAgent.SecurityFinding(
                findingId,
                java.time.Instant.now(),
                parseSeverity((String) findingData.get("severity")),
                (String) findingData.get("category"),
                (String) findingData.get("description"),
                location,
                cveId,
                findingConfidence,
                List.of(recommendation),
                false
            );
            
            // Add feedback to ML model
            unifiedAgent.addFeedback(finding, correctLabel, confidence);
            
            logger.info("Feedback received: {} -> {}", findingId, correctLabel);
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Feedback recorded for continuous learning");
            response.put("feedbackBufferSize", unifiedAgent.getStatistics().get("feedbackSamples"));
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Failed to process feedback: {}", e.getMessage());
            return ResponseEntity.status(500).body(Map.of(
                "success", false,
                "error", e.getMessage()
            ));
        }
    }
    
    /**
     * Trigger manual retraining
     * POST /api/security/retrain
     */
    @PostMapping("/retrain")
    public ResponseEntity<?> triggerRetraining() {
        try {
            logger.info("Manual retraining triggered via API");
            
            // Use virtual thread for async retraining
            CompletableFuture.runAsync(() -> {
                try {
                    // Access retraining via reflection to call private method
                    var method = unifiedAgent.getClass().getDeclaredMethod("retrainModelWithFeedback");
                    method.setAccessible(true);
                    method.invoke(unifiedAgent);
                } catch (Exception e) {
                    logger.error("Manual retraining failed", e);
                }
            });
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Retraining started in background");
            response.put("currentStats", unifiedAgent.getStatistics());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Failed to trigger retraining: {}", e.getMessage());
            return ResponseEntity.status(500).body(Map.of(
                "success", false,
                "error", e.getMessage()
            ));
        }
    }
    
    /**
     * Health check endpoint
     * GET /api/security/health
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("agent", unifiedAgent.getStatus().name());
        health.put("mlModel", "TRAINED");
        health.put("timestamp", java.time.Instant.now());
        return ResponseEntity.ok(health);
    }
    
    /**
     * Get analysis history
     * GET /api/security/history?limit=50&severity=CRITICAL
     */
    @GetMapping("/history")
    public ResponseEntity<Map<String, Object>> getHistory(
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(required = false) String severity) {
        
        // For now, return cached findings (in production, use database)
        Map<String, Object> history = new HashMap<>();
        history.put("totalRecords", 0);
        history.put("limit", limit);
        history.put("severityFilter", severity);
        history.put("records", List.of());
        history.put("message", "History tracking - implement with database for persistence");
        
        return ResponseEntity.ok(history);
    }
    
    /**
     * Get detailed ML metrics
     * GET /api/security/ml-metrics
     */
    @GetMapping("/ml-metrics")
    public ResponseEntity<Map<String, Object>> getMLMetrics() {
        Map<String, Object> stats = unifiedAgent.getStatistics();
        
        Map<String, Object> mlMetrics = new HashMap<>();
        mlMetrics.put("modelType", "AdaBoost Ensemble");
        mlMetrics.put("trainingExamples", 840);
        mlMetrics.put("overallAccuracy", 0.9464);
        mlMetrics.put("vulnerableAccuracy", 1.0);
        mlMetrics.put("safeAccuracy", 1.0);
        mlMetrics.put("suspiciousAccuracy", 0.6538);
        mlMetrics.put("retrainingCount", stats.get("retrainingCount"));
        mlMetrics.put("feedbackSamples", stats.get("feedbackSamples"));
        mlMetrics.put("lastRetrainTime", stats.get("lastRetrainTime"));
        mlMetrics.put("continuousLearning", "ENABLED");
        
        return ResponseEntity.ok(mlMetrics);
    }
    
    /**
     * Apply auto-fix to source code and save to file
     * POST /api/security/apply-fix
     */
    @PostMapping("/apply-fix")
    public ResponseEntity<Map<String, Object>> applyAutoFix(@RequestBody Map<String, String> request) {
        String originalCode = request.get("code");
        String fixCode = request.get("fixCode");
        String filename = request.getOrDefault("filename", "fixed.java");
        String filePath = request.get("filePath"); // Optional: original file path to modify
        
        if (fixCode == null) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "'fixCode' is required"
            ));
        }
        
        try {
            // The fixCode is the actual secure code to use
            String finalCode = fixCode;
            
            // If we have original code, we can try to preserve some structure
            // For now, we'll use the fix code directly as it contains the secure implementation
            
            Path outputPath;
            
            // If filePath provided, save next to original file with -FIXED suffix
            if (filePath != null && !filePath.isBlank()) {
                Path originalPath = Path.of(filePath);
                String originalFilename = originalPath.getFileName().toString();
                String fixedFilename = originalFilename.replace(".java", "-FIXED.java");
                outputPath = originalPath.getParent().resolve(fixedFilename);
            } else {
                // Save to Downloads folder or workspace
                String userHome = System.getProperty("user.home");
                Path downloadsPath = Path.of(userHome, "Downloads");
                String fixedFilename = filename.replace(".java", "-FIXED.java");
                if (!filename.endsWith(".tmp")) { // Don't modify .tmp files
                    outputPath = downloadsPath.resolve(fixedFilename);
                } else {
                    // For temporary files during multi-fix, just return the fixed code
                    Map<String, Object> response = new HashMap<>();
                    response.put("success", true);
                    response.put("originalCode", originalCode);
                    response.put("fixedCode", finalCode);
                    response.put("message", "Fix applied (temporary)");
                    return ResponseEntity.ok(response);
                }
            }
            
            // Write fixed code to file
            Files.writeString(outputPath, finalCode, java.nio.charset.StandardCharsets.UTF_8);
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("originalCode", originalCode);
            response.put("fixedCode", finalCode);
            response.put("savedPath", outputPath.toString());
            response.put("filename", outputPath.getFileName().toString());
            response.put("message", "✓ Fixed code saved to: " + outputPath);
            response.put("note", "Open the file in VS Code to review and use the fixed code.");
            
            logger.info("Auto-fix saved to: {}", outputPath);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            logger.error("Auto-fix failed", e);
            return ResponseEntity.status(500).body(Map.of(
                "success", false,
                "error", "Auto-fix failed: " + e.getMessage()
            ));
        }
    }
    
    /**
     * Analyze code snippet (alternative endpoint)
     * POST /api/security/analyze/snippet
     */
    @PostMapping("/analyze/snippet")
    public ResponseEntity<?> analyzeSnippet(@RequestBody Map<String, String> request) {
        String code = request.get("code");
        String language = request.getOrDefault("language", "java");
        String filename = request.getOrDefault("filename", "snippet." + language);
        
        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "error", "Code is required"
            ));
        }
        
        // Create request object
        CodeAnalysisRequest codeRequest = new CodeAnalysisRequest();
        codeRequest.setCode(code);
        codeRequest.setFilename(filename);
        
        return analyzeCode(codeRequest);
    }
    
    private SecurityAgent.SecurityFinding.Severity parseSeverity(String severity) {
        try {
            return SecurityAgent.SecurityFinding.Severity.valueOf(severity.toUpperCase());
        } catch (Exception e) {
            return SecurityAgent.SecurityFinding.Severity.MEDIUM;
        }
    }
}
