package com.security.ai.unified;

import com.security.ai.agent.SecurityAgent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Unified Feature Extractor - Extracts ML features from security findings
 * 
 * Features extracted:
 * - Vulnerability category (encoded)
 * - Severity level (numeric)
 * - Confidence score
 * - Code complexity metrics
 * - Location-based features
 * - CWE ID (encoded)
 * - Pattern matching scores
 */
public class UnifiedFeatureExtractor {
    
    private static final Logger logger = LoggerFactory.getLogger(UnifiedFeatureExtractor.class);
    
    public Map<String, Double> extractFeatures(SecurityAgent.SecurityFinding finding) {
        Map<String, Double> features = new HashMap<>();
        
        String description = finding.description().toLowerCase();
        String detectionSource = finding.detectionSource() != null ? finding.detectionSource() : "";
        
        // Feature 1: Severity (0-4 scale for training data compatibility)
        features.put("severity", encodeSeverity(finding.severity()));
        
        // Feature 2: Confidence score (0.0-1.0)
        features.put("confidence", finding.confidenceScore());
        
        // Feature 3-7: Vulnerability patterns (binary 0/1)
        features.put("is_sql", (description.contains("sql") || description.contains("injection") || 
                                description.contains("sqli") || finding.category().contains("SQL")) ? 1.0 : 0.0);
        features.put("is_xss", (description.contains("xss") || description.contains("cross-site") || 
                               description.contains("script") || finding.category().contains("XSS")) ? 1.0 : 0.0);
        features.put("is_cmd", (description.contains("command") || description.contains("exec") || 
                               description.contains("rce") || finding.category().contains("Command")) ? 1.0 : 0.0);
        features.put("is_crypto", (description.contains("crypto") || description.contains("encrypt") || 
                                  description.contains("ssl") || description.contains("tls") ||
                                  finding.category().contains("Crypto")) ? 1.0 : 0.0);
        
        // Feature 8: Has CVE/CWE identifier
        features.put("has_cwe", (finding.cveId() != null || description.contains("cve-") || 
                                description.contains("cwe-") || description.contains("osvdb")) ? 1.0 : 0.0);
        
        // Feature 9: Auto-fixable (0/1)
        features.put("is_fixable", finding.autoRemediationPossible() ? 1.0 : 0.0);
        
        // Feature 10: Complexity score (0.0-1.0)
        double complexity = calculateComplexity(description, detectionSource);
        features.put("complexity", complexity);
        
        // Feature 11: External dependency risk (0.0-1.0)
        double depRisk = calculateDependencyRisk(description, detectionSource);
        features.put("dep_risk", depRisk);
        
        return features;
    }
    
    private double calculateComplexity(String description, String source) {
        double score = 0.5; // Base complexity
        
        // Increase for network/dynamic findings
        if (source.contains("MCP") || source.contains("ZAP") || source.contains("DYNAMIC")) {
            score += 0.2;
        }
        
        // Increase for multi-layer vulnerabilities
        if (description.contains("authentication") || description.contains("authorization")) {
            score += 0.15;
        }
        
        if (description.contains("directory") || description.contains("path")) {
            score += 0.1;
        }
        
        return Math.min(1.0, score);
    }
    
    private double calculateDependencyRisk(String description, String source) {
        double risk = 0.3; // Base external risk
        
        // Higher risk for network-based findings
        if (source.contains("MCP-Kali") || source.contains("NMAP") || 
            source.contains("NIKTO") || source.contains("DIRB")) {
            risk += 0.3;
        }
        
        // Higher risk for exposed services
        if (description.contains("open port") || description.contains("exposed") || 
            description.contains("vulnerable")) {
            risk += 0.2;
        }
        
        // Higher risk for outdated components
        if (description.contains("outdated") || description.contains("old version") ||
            description.contains("deprecated")) {
            risk += 0.15;
        }
        
        return Math.min(1.0, risk);
    }
    
    private double encodeSeverity(SecurityAgent.SecurityFinding.Severity severity) {
        return switch (severity) {
            case CRITICAL -> 4.0;
            case HIGH -> 3.0;
            case MEDIUM -> 2.0;
            case LOW -> 1.0;
            default -> 2.0; // Default to MEDIUM
        };
    }
}
