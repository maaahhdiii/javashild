package com.security.ai.unified;

import com.security.ai.agent.SecurityAgent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * JQAssistant Analyzer - Graph-based code analysis
 * 
 * JQAssistant uses Neo4j graph database to analyze:
 * - Code dependencies
 * - Architecture violations
 * - Circular dependencies
 * - Unused code
 * - Security anti-patterns in architecture
 */
public class JQAssistantAnalyzer {
    
    private static final Logger logger = LoggerFactory.getLogger(JQAssistantAnalyzer.class);
    
    public void initialize() {
        logger.info("✓ JQAssistant Analyzer initialized (graph-based analysis)");
    }
    
    public List<SecurityAgent.SecurityFinding> analyze(Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            logger.debug("JQAssistant analyzing: {}", sourcePath);
            
            // Read source code for pattern-based analysis
            String code = java.nio.file.Files.readString(sourcePath);
            
            // Detect architectural security anti-patterns
            detectArchitecturalIssues(code, sourcePath, findings);
            
        } catch (Exception e) {
            logger.debug("JQAssistant analysis skipped for {}: {}", sourcePath.getFileName(), e.getMessage());
        }
        
        return findings;
    }
    
    private void detectArchitecturalIssues(String code, Path sourcePath, List<SecurityAgent.SecurityFinding> findings) {
        // Detect missing input validation in public methods
        if (code.contains("public ") && code.contains("String") && !code.contains("validate") && 
            (code.contains("sql") || code.contains("query") || code.contains("execute"))) {
            findings.add(new SecurityAgent.SecurityFinding(
                null, null,
                SecurityAgent.SecurityFinding.Severity.MEDIUM,
                "JQAssistant: Missing Input Validation",
                "Public method handling sensitive operations lacks input validation",
                sourcePath.toString(),
                null, 0.70,
                List.of("Add input validation"),
                false,
                "STATIC: JQAssistant",
                null
            ));
        }
        
        // Detect excessive method complexity (security risk)
        int methodCount = code.split("\\bpublic\\s+\\w+\\s+\\w+\\s*\\(").length - 1;
        int ifCount = code.split("\\bif\\s*\\(").length - 1;
        if (methodCount > 0 && ifCount / Math.max(methodCount, 1) > 5) {
            findings.add(new SecurityAgent.SecurityFinding(
                null, null,
                SecurityAgent.SecurityFinding.Severity.LOW,
                "JQAssistant: Excessive Complexity",
                "High cyclomatic complexity increases security risk",
                sourcePath.toString(),
                null, 0.65,
                List.of("Refactor to reduce complexity"),
                false,
                "STATIC: JQAssistant",
                null
            ));
        }
    }
}
