package com.security.ai.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.ai.agent.AgentOrchestrator;
import com.security.ai.agent.SecurityAgent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * CI/CD integration layer for security agents.
 * Integrates with Jenkins, GitHub Actions, GitLab CI/CD for automated security scanning.
 */
public class CICDIntegrationService {
    
    private static final Logger logger = LoggerFactory.getLogger(CICDIntegrationService.class);
    
    private final AgentOrchestrator orchestrator;
    private final ObjectMapper objectMapper;
    
    public CICDIntegrationService(AgentOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Scan source code repository (called from CI/CD pipeline)
     */
    public ScanResult scanRepository(Path repositoryPath, ScanConfiguration config) {
        logger.info("Starting CI/CD security scan for: {}", repositoryPath);
        
        long startTime = System.currentTimeMillis();
        List<SecurityAgent.SecurityFinding> allFindings = new ArrayList<>();
        
        try {
            // Scan all Java files in repository
            List<Path> javaFiles = findJavaFiles(repositoryPath);
            logger.info("Found {} Java files to scan", javaFiles.size());
            
            List<CompletableFuture<List<SecurityAgent.SecurityFinding>>> scanFutures = 
                new ArrayList<>();
            
            for (Path javaFile : javaFiles) {
                SecurityAgent.SecurityEvent event = new SecurityAgent.SecurityEvent(
                    null,
                    null,
                    SecurityAgent.SecurityEvent.EventType.CODE_CHANGE,
                    "CI/CD Scanner",
                    javaFile
                );
                
                CompletableFuture<List<SecurityAgent.SecurityFinding>> future = 
                    orchestrator.analyzeEvent(event)
                        .thenApply(aggregated -> aggregated.findings());
                
                scanFutures.add(future);
            }
            
            // Wait for all scans to complete
            CompletableFuture.allOf(scanFutures.toArray(new CompletableFuture[0])).join();
            
            // Aggregate all findings
            for (CompletableFuture<List<SecurityAgent.SecurityFinding>> future : scanFutures) {
                allFindings.addAll(future.get());
            }
            
            long duration = System.currentTimeMillis() - startTime;
            
            // Filter findings based on configuration
            List<SecurityAgent.SecurityFinding> filteredFindings = 
                filterFindings(allFindings, config);
            
            // Determine if build should fail
            boolean shouldFail = shouldFailBuild(filteredFindings, config);
            
            ScanResult result = new ScanResult(
                repositoryPath.toString(),
                filteredFindings.size(),
                countBySeverity(filteredFindings),
                filteredFindings,
                shouldFail,
                duration,
                new Date()
            );
            
            logger.info("CI/CD security scan completed: {} findings in {}ms", 
                filteredFindings.size(), duration);
            
            return result;
            
        } catch (Exception e) {
            logger.error("CI/CD security scan failed", e);
            return new ScanResult(
                repositoryPath.toString(),
                0,
                Collections.emptyMap(),
                Collections.emptyList(),
                true,
                System.currentTimeMillis() - startTime,
                new Date()
            );
        }
    }
    
    /**
     * Generate Jenkins pipeline integration script
     */
    public String generateJenkinsPipeline(String projectName) {
        return """
            pipeline {
                agent any
                
                stages {
                    stage('Checkout') {
                        steps {
                            checkout scm
                        }
                    }
                    
                    stage('Security Scan') {
                        steps {
                            script {
                                // Run AI security agent
                                sh '''
                                    java -jar vulnerability-detection-agent.jar \\
                                        --scan ${WORKSPACE} \\
                                        --output scan-results.json \\
                                        --fail-on-critical true
                                '''
                            }
                        }
                    }
                    
                    stage('Publish Results') {
                        steps {
                            archiveArtifacts artifacts: 'scan-results.json'
                            
                            script {
                                def scanResults = readJSON file: 'scan-results.json'
                                
                                if (scanResults.shouldFail) {
                                    error("Security scan failed: ${scanResults.totalFindings} vulnerabilities found")
                                }
                            }
                        }
                    }
                }
                
                post {
                    always {
                        // Cleanup
                        cleanWs()
                    }
                    failure {
                        // Notify security team
                        emailext(
                            subject: "Security Scan Failed: %s",
                            body: "Security vulnerabilities detected in build",
                            to: "security@example.com"
                        )
                    }
                }
            }
            """.formatted(projectName);
    }
    
    /**
     * Generate GitHub Actions workflow
     */
    public String generateGitHubActionsWorkflow(String projectName) {
        return """
            name: Security Scan
            
            on:
              push:
                branches: [ main, develop ]
              pull_request:
                branches: [ main, develop ]
            
            jobs:
              security-scan:
                runs-on: ubuntu-latest
                
                steps:
                  - name: Checkout code
                    uses: actions/checkout@v3
                  
                  - name: Set up Java 25
                    uses: actions/setup-java@v3
                    with:
                      java-version: '25'
                      distribution: 'temurin'
                  
                  - name: Run Security Scan
                    run: |
                      java -jar vulnerability-detection-agent.jar \\
                        --scan ${{ github.workspace }} \\
                        --output scan-results.json \\
                        --fail-on-critical true
                  
                  - name: Upload scan results
                    uses: actions/upload-artifact@v3
                    if: always()
                    with:
                      name: security-scan-results
                      path: scan-results.json
                  
                  - name: Comment on PR
                    if: github.event_name == 'pull_request'
                    uses: actions/github-script@v6
                    with:
                      script: |
                        const fs = require('fs');
                        const results = JSON.parse(fs.readFileSync('scan-results.json', 'utf8'));
                        
                        const comment = `## Security Scan Results
                        
                        **Total Findings:** ${results.totalFindings}
                        **Critical:** ${results.severityCounts.CRITICAL || 0}
                        **High:** ${results.severityCounts.HIGH || 0}
                        **Medium:** ${results.severityCounts.MEDIUM || 0}
                        **Low:** ${results.severityCounts.LOW || 0}
                        
                        ${results.shouldFail ? '❌ Build failed due to security vulnerabilities' : '✅ No critical vulnerabilities found'}
                        `;
                        
                        github.rest.issues.createComment({
                          issue_number: context.issue.number,
                          owner: context.repo.owner,
                          repo: context.repo.repo,
                          body: comment
                        });
            """;
    }
    
    /**
     * Generate GitLab CI/CD configuration
     */
    public String generateGitLabCIConfig(String projectName) {
        return """
            stages:
              - security
              - report
            
            security_scan:
              stage: security
              image: eclipse-temurin:25-jdk
              script:
                - java -jar vulnerability-detection-agent.jar
                    --scan $CI_PROJECT_DIR
                    --output scan-results.json
                    --fail-on-critical true
              artifacts:
                reports:
                  junit: scan-results.json
                paths:
                  - scan-results.json
                expire_in: 30 days
              allow_failure: false
            
            security_report:
              stage: report
              image: alpine:latest
              script:
                - cat scan-results.json
              dependencies:
                - security_scan
              when: always
            """;
    }
    
    /**
     * Find all Java files in repository
     */
    private List<Path> findJavaFiles(Path repositoryPath) throws Exception {
        List<Path> javaFiles = new ArrayList<>();
        
        java.nio.file.Files.walk(repositoryPath)
            .filter(p -> p.toString().endsWith(".java"))
            .filter(p -> !p.toString().contains("/test/"))
            .filter(p -> !p.toString().contains("/target/"))
            .filter(p -> !p.toString().contains("/build/"))
            .forEach(javaFiles::add);
        
        return javaFiles;
    }
    
    /**
     * Filter findings based on configuration
     */
    private List<SecurityAgent.SecurityFinding> filterFindings(
        List<SecurityAgent.SecurityFinding> findings,
        ScanConfiguration config
    ) {
        return findings.stream()
            .filter(f -> f.confidenceScore() >= config.minConfidence())
            .filter(f -> shouldIncludeSeverity(f.severity(), config.minSeverity()))
            .toList();
    }
    
    /**
     * Check if severity should be included
     */
    private boolean shouldIncludeSeverity(
        SecurityAgent.SecurityFinding.Severity severity,
        SecurityAgent.SecurityFinding.Severity minSeverity
    ) {
        return severity.getWeight() >= minSeverity.getWeight();
    }
    
    /**
     * Count findings by severity
     */
    private Map<String, Integer> countBySeverity(List<SecurityAgent.SecurityFinding> findings) {
        Map<String, Integer> counts = new HashMap<>();
        
        for (SecurityAgent.SecurityFinding finding : findings) {
            String severity = finding.severity().name();
            counts.put(severity, counts.getOrDefault(severity, 0) + 1);
        }
        
        return counts;
    }
    
    /**
     * Determine if build should fail based on findings
     */
    private boolean shouldFailBuild(
        List<SecurityAgent.SecurityFinding> findings,
        ScanConfiguration config
    ) {
        if (config.failOnCritical()) {
            long criticalCount = findings.stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL)
                .count();
            
            if (criticalCount > 0) {
                return true;
            }
        }
        
        if (config.failOnHigh()) {
            long highCount = findings.stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH)
                .count();
            
            if (highCount > config.maxHighSeverityFindings()) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Export scan results in various formats
     */
    public void exportResults(ScanResult result, File outputFile, ExportFormat format) {
        try {
            switch (format) {
                case JSON -> exportJSON(result, outputFile);
                case SARIF -> exportSARIF(result, outputFile);
                case HTML -> exportHTML(result, outputFile);
                case JUNIT -> exportJUnit(result, outputFile);
            }
            
            logger.info("Exported scan results to: {}", outputFile);
            
        } catch (Exception e) {
            logger.error("Failed to export scan results", e);
        }
    }
    
    private void exportJSON(ScanResult result, File outputFile) throws Exception {
        objectMapper.writerWithDefaultPrettyPrinter()
            .writeValue(outputFile, result);
    }
    
    private void exportSARIF(ScanResult result, File outputFile) throws Exception {
        // SARIF format for GitHub Code Scanning
        Map<String, Object> sarif = new HashMap<>();
        sarif.put("version", "2.1.0");
        sarif.put("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        
        List<Map<String, Object>> runs = new ArrayList<>();
        Map<String, Object> run = new HashMap<>();
        
        List<Map<String, Object>> results = new ArrayList<>();
        for (SecurityAgent.SecurityFinding finding : result.findings()) {
            Map<String, Object> sarifResult = new HashMap<>();
            sarifResult.put("ruleId", finding.category());
            sarifResult.put("level", mapSeverityToSARIF(finding.severity()));
            sarifResult.put("message", Map.of("text", finding.description()));
            
            Map<String, Object> location = new HashMap<>();
            location.put("physicalLocation", Map.of(
                "artifactLocation", Map.of("uri", finding.location())
            ));
            sarifResult.put("locations", List.of(location));
            
            results.add(sarifResult);
        }
        
        run.put("results", results);
        runs.add(run);
        sarif.put("runs", runs);
        
        objectMapper.writerWithDefaultPrettyPrinter()
            .writeValue(outputFile, sarif);
    }
    
    private void exportHTML(ScanResult result, File outputFile) throws Exception {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>Security Scan Report</title>");
        html.append("<style>body{font-family:Arial;margin:20px;}");
        html.append(".critical{color:red;}.high{color:orange;}.medium{color:yellow;}.low{color:green;}</style>");
        html.append("</head><body>");
        html.append("<h1>Security Scan Report</h1>");
        html.append("<p>Repository: ").append(result.repositoryPath()).append("</p>");
        html.append("<p>Total Findings: ").append(result.totalFindings()).append("</p>");
        html.append("<p>Scan Date: ").append(result.scanDate()).append("</p>");
        
        html.append("<h2>Findings by Severity</h2><ul>");
        result.severityCounts().forEach((severity, count) -> 
            html.append("<li>").append(severity).append(": ").append(count).append("</li>"));
        html.append("</ul>");
        
        html.append("<h2>Detailed Findings</h2>");
        for (SecurityAgent.SecurityFinding finding : result.findings()) {
            html.append("<div class='").append(finding.severity().name().toLowerCase()).append("'>");
            html.append("<h3>").append(finding.category()).append("</h3>");
            html.append("<p>").append(finding.description()).append("</p>");
            html.append("<p>Location: ").append(finding.location()).append("</p>");
            html.append("<p>Confidence: ").append(finding.confidenceScore()).append("</p>");
            html.append("</div>");
        }
        
        html.append("</body></html>");
        
        java.nio.file.Files.writeString(outputFile.toPath(), html.toString());
    }
    
    private void exportJUnit(ScanResult result, File outputFile) throws Exception {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version='1.0' encoding='UTF-8'?>");
        xml.append("<testsuite name='Security Scan' tests='").append(result.totalFindings()).append("'>");
        
        for (SecurityAgent.SecurityFinding finding : result.findings()) {
            xml.append("<testcase name='").append(finding.category()).append("' ");
            xml.append("classname='").append(finding.location()).append("'>");
            
            if (finding.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL ||
                finding.severity() == SecurityAgent.SecurityFinding.Severity.HIGH) {
                xml.append("<failure message='").append(finding.description()).append("'/>");
            }
            
            xml.append("</testcase>");
        }
        
        xml.append("</testsuite>");
        
        java.nio.file.Files.writeString(outputFile.toPath(), xml.toString());
    }
    
    private String mapSeverityToSARIF(SecurityAgent.SecurityFinding.Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW, INFO -> "note";
        };
    }
    
    /**
     * Scan configuration
     */
    public record ScanConfiguration(
        SecurityAgent.SecurityFinding.Severity minSeverity,
        double minConfidence,
        boolean failOnCritical,
        boolean failOnHigh,
        int maxHighSeverityFindings
    ) {
        public static ScanConfiguration defaultConfig() {
            return new ScanConfiguration(
                SecurityAgent.SecurityFinding.Severity.LOW,
                0.5,
                true,
                true,
                5
            );
        }
    }
    
    /**
     * Scan result
     */
    public record ScanResult(
        String repositoryPath,
        int totalFindings,
        Map<String, Integer> severityCounts,
        List<SecurityAgent.SecurityFinding> findings,
        boolean shouldFail,
        long durationMs,
        Date scanDate
    ) {}
    
    /**
     * Export format enum
     */
    public enum ExportFormat {
        JSON,
        SARIF,
        HTML,
        JUNIT
    }
}
