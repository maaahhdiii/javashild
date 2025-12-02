package com.security.ai;

import com.security.ai.agent.AgentOrchestrator;
import com.security.ai.agent.SecurityAgent;
import com.security.ai.analysis.dynamicanalysis.DynamicAnalysisAgent;
import com.security.ai.analysis.staticanalysis.StaticAnalysisAgent;
import com.security.ai.integration.CICDIntegrationService;
import com.security.ai.ml.MLClassificationAgent;
import com.security.ai.response.AutomatedResponseAgent;
import com.security.ai.vulnerabilitydb.VulnerabilityDatabaseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

/**
 * Main application demonstrating AI-driven vulnerability detection, handling, and blocking.
 * This demo showcases real-time security monitoring with automated response capabilities.
 */
public class SecurityAgentDemo {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityAgentDemo.class);
    
    public static void main(String[] args) {
        logger.info("=".repeat(80));
        logger.info("AI Agent for Vulnerability Detection, Handling and Blocking");
        logger.info("Java 25 - Advanced Security Automation System");
        logger.info("=".repeat(80));
        
        try {
            // Parse command line arguments
            DemoConfiguration config = parseArguments(args);
            
            if (config.mode() == DemoMode.HELP) {
                printUsage();
                return;
            }
            
            // Run demo based on mode
            switch (config.mode()) {
                case FULL_DEMO -> runFullDemo(config);
                case SCAN_ONLY -> runScanOnly(config);
                case CICD_INTEGRATION -> runCICDIntegration(config);
                case LIVE_MONITORING -> runLiveMonitoring(config);
            }
            
        } catch (Exception e) {
            logger.error("Demo execution failed", e);
            System.exit(1);
        }
    }
    
    /**
     * Run full demonstration with all agents
     */
    private static void runFullDemo(DemoConfiguration config) throws Exception {
        logger.info("\n" + "=".repeat(80));
        logger.info("RUNNING FULL DEMO - All Security Agents");
        logger.info("=".repeat(80) + "\n");
        
        // Initialize orchestrator
        AgentOrchestrator orchestrator = new AgentOrchestrator();
        
        // Register all agents
        logger.info("Step 1: Initializing Security Agents...");
        
        StaticAnalysisAgent staticAgent = new StaticAnalysisAgent();
        DynamicAnalysisAgent dynamicAgent = new DynamicAnalysisAgent();
        MLClassificationAgent mlAgent = new MLClassificationAgent();
        AutomatedResponseAgent responseAgent = new AutomatedResponseAgent();
        
        orchestrator.registerAgent(staticAgent);
        orchestrator.registerAgent(dynamicAgent);
        orchestrator.registerAgent(mlAgent);
        orchestrator.registerAgent(responseAgent);
        
        logger.info("✓ Registered {} security agents", orchestrator.getAgentStatistics().size());
        
        // Start all agents
        logger.info("\nStep 2: Starting All Agents...");
        orchestrator.startAll();
        Thread.sleep(2000); // Let agents initialize
        logger.info("✓ All agents are running\n");
        
        // Demo 1: Static Analysis
        logger.info("Demo 1: Static Code Analysis");
        logger.info("-".repeat(80));
        demonstrateStaticAnalysis(orchestrator, config.targetPath());
        
        // Demo 2: Dynamic Analysis
        logger.info("\nDemo 2: Runtime Behavior Monitoring");
        logger.info("-".repeat(80));
        demonstrateDynamicAnalysis(orchestrator);
        
        // Demo 3: ML Classification
        logger.info("\nDemo 3: ML-Based Risk Assessment");
        logger.info("-".repeat(80));
        demonstrateMLClassification(orchestrator);
        
        // Demo 4: Automated Response
        logger.info("\nDemo 4: Automated Threat Response");
        logger.info("-".repeat(80));
        demonstrateAutomatedResponse(orchestrator);
        
        // Demo 5: Vulnerability Database Integration
        logger.info("\nDemo 5: Vulnerability Database Integration");
        logger.info("-".repeat(80));
        demonstrateVulnerabilityDB();
        
        // Stop all agents
        logger.info("\nStopping all agents...");
        orchestrator.stopAll();
        
        logger.info("\n" + "=".repeat(80));
        logger.info("DEMO COMPLETED SUCCESSFULLY");
        logger.info("=".repeat(80));
    }
    
    /**
     * Demonstrate static analysis capabilities
     */
    private static void demonstrateStaticAnalysis(AgentOrchestrator orchestrator, Path targetPath) 
            throws Exception {
        
        // Create a vulnerable code sample
        Path vulnerableFile = createVulnerableCodeSample();
        
        SecurityAgent.SecurityEvent event = new SecurityAgent.SecurityEvent(
            null,
            null,
            SecurityAgent.SecurityEvent.EventType.CODE_CHANGE,
            "Demo",
            vulnerableFile
        );
        
        var result = orchestrator.analyzeEvent(event).get(10, TimeUnit.SECONDS);
        
        logger.info("Analyzed file: {}", vulnerableFile);
        logger.info("Found {} potential vulnerabilities", result.findings().size());
        
        for (SecurityAgent.SecurityFinding finding : result.findings()) {
            logger.info("  → {} [{}] - Confidence: {}", 
                finding.category(), 
                finding.severity(), 
                String.format("%.2f", finding.confidenceScore()));
        }
        
        logger.info("Critical findings: {}", result.getCriticalFindings().size());
        logger.info("High severity findings: {}", result.getHighSeverityFindings().size());
    }
    
    /**
     * Demonstrate dynamic analysis capabilities
     */
    private static void demonstrateDynamicAnalysis(AgentOrchestrator orchestrator) throws Exception {
        
        // Simulate runtime behavior events
        SecurityAgent.SecurityEvent networkEvent = new SecurityAgent.SecurityEvent(
            null,
            null,
            SecurityAgent.SecurityEvent.EventType.NETWORK_REQUEST,
            "Demo",
            new DynamicAnalysisAgent.NetworkRequestInfo(
                "http",
                "suspicious-domain.ru",
                80,
                "/api/data",
                "com.example.App.sendData()"
            )
        );
        
        var result = orchestrator.analyzeEvent(networkEvent).get(5, TimeUnit.SECONDS);
        
        logger.info("Analyzed network request to: suspicious-domain.ru");
        logger.info("Security findings: {}", result.findings().size());
        
        if (result.hasBlockableThreats()) {
            logger.warn("⚠ BLOCKABLE THREATS DETECTED - Automated response will be triggered");
        }
    }
    
    /**
     * Demonstrate ML classification capabilities
     */
    private static void demonstrateMLClassification(AgentOrchestrator orchestrator) throws Exception {
        
        // Create sample finding for ML enhancement
        SecurityAgent.SecurityFinding sampleFinding = new SecurityAgent.SecurityFinding(
            null,
            null,
            SecurityAgent.SecurityFinding.Severity.HIGH,
            "SQL Injection",
            "Potential SQL injection in user input handling",
            "com.example.UserService.java:45",
            "CWE-89",
            0.75,
            java.util.List.of("Use PreparedStatement", "Validate input"),
            true
        );
        
        SecurityAgent.SecurityEvent mlEvent = new SecurityAgent.SecurityEvent(
            null,
            null,
            SecurityAgent.SecurityEvent.EventType.CODE_CHANGE,
            "Demo",
            java.util.List.of(sampleFinding)
        );
        
        var result = orchestrator.analyzeEvent(mlEvent).get(5, TimeUnit.SECONDS);
        
        logger.info("ML Risk Assessment completed");
        logger.info("Average confidence: {}", String.format("%.2f", result.getAverageConfidence()));
        logger.info("Findings after ML enhancement: {}", result.findings().size());
    }
    
    /**
     * Demonstrate automated response capabilities
     */
    private static void demonstrateAutomatedResponse(AgentOrchestrator orchestrator) throws Exception {
        
        // Create critical finding that should trigger blocking
        SecurityAgent.SecurityFinding criticalFinding = new SecurityAgent.SecurityFinding(
            null,
            null,
            SecurityAgent.SecurityFinding.Severity.CRITICAL,
            "Remote Code Execution",
            "Remote code execution vulnerability detected",
            "com.example.FileUpload.java:78",
            "CWE-94",
            0.95,
            java.util.List.of("Block file upload", "Implement validation"),
            true
        );
        
        SecurityAgent.SecurityEvent responseEvent = new SecurityAgent.SecurityEvent(
            null,
            null,
            SecurityAgent.SecurityEvent.EventType.CODE_CHANGE,
            "Demo",
            criticalFinding
        );
        
        var result = orchestrator.analyzeEvent(responseEvent).get(5, TimeUnit.SECONDS);
        
        logger.info("Automated response triggered for critical vulnerability");
        logger.info("Response actions scheduled: {}", result.findings().size());
        
        Thread.sleep(2000); // Allow response actions to execute
    }
    
    /**
     * Demonstrate vulnerability database integration
     */
    private static void demonstrateVulnerabilityDB() throws Exception {
        
        VulnerabilityDatabaseService dbService = new VulnerabilityDatabaseService();
        
        // Example: Fetch CVE details
        logger.info("Fetching CVE-2021-44228 (Log4Shell) details from NVD...");
        
        var cveDetails = dbService.fetchCVEDetails("CVE-2021-44228");
        
        if (cveDetails.isPresent()) {
            var cve = cveDetails.get();
            logger.info("  CVE ID: {}", cve.cveId());
            logger.info("  Severity: {}", cve.severity());
            logger.info("  CVSS Score: {}", cve.cvssV3Score());
            logger.info("  Description: {}", 
                cve.description().substring(0, Math.min(100, cve.description().length())) + "...");
        } else {
            logger.info("  (Note: Requires network connection to NVD)");
        }
        
        // Example: Search vulnerabilities
        logger.info("\nSearching for recent SQL injection vulnerabilities...");
        var searchResults = dbService.searchVulnerabilities("SQL injection", 5);
        logger.info("  Found {} vulnerabilities", searchResults.size());
    }
    
    /**
     * Run scan-only mode (for CI/CD)
     */
    private static void runScanOnly(DemoConfiguration config) throws Exception {
        logger.info("Running Security Scan on: {}", config.targetPath());
        
        AgentOrchestrator orchestrator = new AgentOrchestrator();
        orchestrator.registerAgent(new StaticAnalysisAgent());
        orchestrator.startAll();
        
        Thread.sleep(2000);
        
        CICDIntegrationService cicdService = new CICDIntegrationService(orchestrator);
        var scanResult = cicdService.scanRepository(
            config.targetPath(),
            CICDIntegrationService.ScanConfiguration.defaultConfig()
        );
        
        logger.info("Scan completed:");
        logger.info("  Total findings: {}", scanResult.totalFindings());
        logger.info("  Duration: {}ms", scanResult.durationMs());
        logger.info("  Should fail build: {}", scanResult.shouldFail());
        
        // Export results
        File outputFile = new File("scan-results.json");
        cicdService.exportResults(scanResult, outputFile, 
            CICDIntegrationService.ExportFormat.JSON);
        logger.info("  Results exported to: {}", outputFile.getAbsolutePath());
        
        orchestrator.stopAll();
        
        if (scanResult.shouldFail()) {
            System.exit(1);
        }
    }
    
    /**
     * Run CI/CD integration demo
     */
    private static void runCICDIntegration(DemoConfiguration config) throws Exception {
        logger.info("Generating CI/CD Integration Configurations...\n");
        
        AgentOrchestrator orchestrator = new AgentOrchestrator();
        CICDIntegrationService cicdService = new CICDIntegrationService(orchestrator);
        
        // Generate pipeline configurations
        logger.info("Jenkins Pipeline:");
        logger.info("-".repeat(80));
        System.out.println(cicdService.generateJenkinsPipeline("demo-project"));
        
        logger.info("\nGitHub Actions Workflow:");
        logger.info("-".repeat(80));
        System.out.println(cicdService.generateGitHubActionsWorkflow("demo-project"));
        
        logger.info("\nGitLab CI Configuration:");
        logger.info("-".repeat(80));
        System.out.println(cicdService.generateGitLabCIConfig("demo-project"));
    }
    
    /**
     * Run live monitoring mode
     */
    private static void runLiveMonitoring(DemoConfiguration config) throws Exception {
        logger.info("Starting Live Security Monitoring...");
        logger.info("Press Ctrl+C to stop\n");
        
        AgentOrchestrator orchestrator = new AgentOrchestrator();
        
        orchestrator.registerAgent(new StaticAnalysisAgent());
        orchestrator.registerAgent(new DynamicAnalysisAgent());
        orchestrator.registerAgent(new MLClassificationAgent());
        orchestrator.registerAgent(new AutomatedResponseAgent());
        
        orchestrator.startAll();
        
        // Add shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("\nShutting down security monitoring...");
            orchestrator.stopAll();
        }));
        
        // Keep running
        Thread.currentThread().join();
    }
    
    /**
     * Create a vulnerable code sample for demonstration
     */
    private static Path createVulnerableCodeSample() throws Exception {
        Path tempFile = java.nio.file.Files.createTempFile("VulnerableCode", ".java");
        
        String vulnerableCode = """
            package com.example;
            
            import java.sql.*;
            
            public class VulnerableCode {
                private static final String PASSWORD = "admin123"; // Hardcoded credential
                
                public User login(String username, String password) throws SQLException {
                    Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
                    
                    // SQL Injection vulnerability
                    String query = "SELECT * FROM users WHERE username='" + username + 
                                   "' AND password='" + password + "'";
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery(query);
                    
                    if (rs.next()) {
                        return new User(rs.getString("username"));
                    }
                    return null;
                }
            }
            """;
        
        java.nio.file.Files.writeString(tempFile, vulnerableCode);
        return tempFile;
    }
    
    /**
     * Parse command line arguments
     */
    private static DemoConfiguration parseArguments(String[] args) {
        if (args.length == 0) {
            return new DemoConfiguration(DemoMode.FULL_DEMO, Paths.get("."));
        }
        
        DemoMode mode = DemoMode.FULL_DEMO;
        Path targetPath = Paths.get(".");
        
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help", "-h" -> mode = DemoMode.HELP;
                case "--scan" -> mode = DemoMode.SCAN_ONLY;
                case "--cicd" -> mode = DemoMode.CICD_INTEGRATION;
                case "--monitor" -> mode = DemoMode.LIVE_MONITORING;
                case "--path" -> {
                    if (i + 1 < args.length) {
                        targetPath = Paths.get(args[++i]);
                    }
                }
            }
        }
        
        return new DemoConfiguration(mode, targetPath);
    }
    
    /**
     * Print usage information
     */
    private static void printUsage() {
        System.out.println("""
            
            AI Agent for Vulnerability Detection, Handling and Blocking
            Java 25 - Advanced Security Automation System
            
            Usage: java -jar vulnerability-detection-agent.jar [OPTIONS]
            
            Options:
              --help, -h          Show this help message
              --scan              Run security scan only (for CI/CD)
              --cicd              Generate CI/CD integration configurations
              --monitor           Run live security monitoring
              --path <PATH>       Target path to scan (default: current directory)
            
            Examples:
              # Run full demo
              java -jar vulnerability-detection-agent.jar
              
              # Scan specific project
              java -jar vulnerability-detection-agent.jar --scan --path /path/to/project
              
              # Generate CI/CD configurations
              java -jar vulnerability-detection-agent.jar --cicd
              
              # Start live monitoring
              java -jar vulnerability-detection-agent.jar --monitor
            
            """);
    }
    
    /**
     * Demo configuration
     */
    record DemoConfiguration(DemoMode mode, Path targetPath) {}
    
    /**
     * Demo mode enum
     */
    enum DemoMode {
        FULL_DEMO,
        SCAN_ONLY,
        CICD_INTEGRATION,
        LIVE_MONITORING,
        HELP
    }
}
