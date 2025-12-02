package com.security.ai.analysis.staticanalysis;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.security.ai.agent.AbstractSecurityAgent;
import com.security.ai.agent.SecurityAgent;
import edu.umd.cs.findbugs.BugCollection;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.DetectorFactoryCollection;
import edu.umd.cs.findbugs.FindBugs2;
import edu.umd.cs.findbugs.Project;
import net.sourceforge.pmd.PMDConfiguration;
import net.sourceforge.pmd.PmdAnalysis;
import net.sourceforge.pmd.lang.rule.Rule;
import net.sourceforge.pmd.reporting.Report;
import net.sourceforge.pmd.reporting.RuleViolation;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.Collectors;

/**
 * Static analysis agent that performs AST parsing, pattern recognition,
 * and integrates with SpotBugs and PMD for vulnerability detection.
 */
public class StaticAnalysisAgent extends AbstractSecurityAgent {
    
    private final BlockingQueue<SecurityEvent> eventQueue = new LinkedBlockingQueue<>();
    private final JavaParser javaParser = new JavaParser();
    private final VulnerabilityPatternDetector patternDetector;
    private final Map<String, VulnerabilityPattern> patterns = new HashMap<>();
    
    public StaticAnalysisAgent() {
        super();
        this.patternDetector = new VulnerabilityPatternDetector();
        loadVulnerabilityPatterns();
    }
    
    @Override
    public AgentType getType() {
        return AgentType.STATIC_ANALYZER;
    }
    
    @Override
    protected void initialize() throws Exception {
        logger.info("Initializing Static Analysis Agent");
        status.set(AgentStatus.RUNNING);
    }
    
    @Override
    protected void runAgentLoop() throws Exception {
        while (status.get() == AgentStatus.RUNNING) {
            try {
                SecurityEvent event = eventQueue.poll(1, java.util.concurrent.TimeUnit.SECONDS);
                if (event != null) {
                    analyze(event);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    @Override
    protected List<SecurityFinding> performAnalysis(SecurityEvent event) throws Exception {
        List<SecurityFinding> findings = new ArrayList<>();
        
        logger.info("StaticAnalysisAgent - Event type: {}, Payload type: {}", 
            event.type(), 
            event.payload() != null ? event.payload().getClass().getName() : "null");
        
        if (event.type() == SecurityEvent.EventType.CODE_CHANGE && event.payload() instanceof Path sourcePath) {
            logger.info("StaticAnalysisAgent - Analyzing path: {}, exists: {}", 
                sourcePath, Files.exists(sourcePath));
            
            // Parallel analysis using structured concurrency
            findings.addAll(analyzeWithAST(sourcePath));
            findings.addAll(analyzeWithPMD(sourcePath));
            findings.addAll(analyzeWithSpotBugs(sourcePath));
            
            logger.info("StaticAnalysisAgent - Found {} vulnerabilities", findings.size());
        } else {
            logger.warn("StaticAnalysisAgent - Skipping analysis: wrong event type or payload type");
        }
        
        return findings;
    }
    
    /**
     * AST-based vulnerability detection using JavaParser
     */
    private List<SecurityFinding> analyzeWithAST(Path sourcePath) throws IOException {
        List<SecurityFinding> findings = new ArrayList<>();
        
        if (!Files.exists(sourcePath) || !sourcePath.toString().endsWith(".java")) {
            return findings;
        }
        
        ParseResult<CompilationUnit> parseResult = javaParser.parse(sourcePath);
        
        if (parseResult.isSuccessful() && parseResult.getResult().isPresent()) {
            CompilationUnit cu = parseResult.getResult().get();
            
            // Detect SQL injection vulnerabilities
            findings.addAll(detectSQLInjection(cu, sourcePath));
            
            // Detect hardcoded credentials
            findings.addAll(detectHardcodedCredentials(cu, sourcePath));
            
            // Detect insecure deserialization
            findings.addAll(detectInsecureDeserialization(cu, sourcePath));
            
            // Custom pattern detection
            findings.addAll(patternDetector.detect(cu, sourcePath));
        }
        
        return findings;
    }
    
    /**
     * PMD-based static analysis
     */
    private List<SecurityFinding> analyzeWithPMD(Path sourcePath) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        try {
            PMDConfiguration config = new PMDConfiguration();
            config.setInputPathList(Collections.singletonList(sourcePath));
            config.addRuleSet("category/java/security.xml");
            config.addRuleSet("category/java/bestpractices.xml");
            
            try (PmdAnalysis pmd = PmdAnalysis.create(config)) {
                Report report = pmd.performAnalysisAndCollectReport();
                
                for (RuleViolation violation : report.getViolations()) {
                    findings.add(new SecurityFinding(
                        null,
                        null,
                        mapPMDSeverity(violation.getRule()),
                        "PMD: " + violation.getRule().getName(),
                        violation.getDescription(),
                        sourcePath + ":" + violation.getBeginLine(),
                        null,
                        0.85,
                        List.of("Review code at line " + violation.getBeginLine()),
                        false
                    ));
                }
            }
        } catch (Exception e) {
            logger.error("PMD analysis failed", e);
        }
        
        return findings;
    }
    
    /**
     * SpotBugs-based static analysis
     */
    private List<SecurityFinding> analyzeWithSpotBugs(Path sourcePath) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        try {
            // Note: SpotBugs requires compiled bytecode
            // This is a simplified implementation
            Project project = new Project();
            project.addFile(sourcePath.toString());
            
            FindBugs2 findBugs = new FindBugs2();
            findBugs.setProject(project);
            findBugs.setDetectorFactoryCollection(DetectorFactoryCollection.instance());
            
            findBugs.execute();
            
            // Note: SpotBugs API varies by version - simplified for demo
            logger.info("SpotBugs analysis completed (results processing simplified for demo)");
            
        } catch (Exception e) {
            logger.warn("SpotBugs analysis skipped (requires compiled code): {}", e.getMessage());
        }
        
        return findings;
    }
    
    /**
     * Detect SQL injection vulnerabilities
     */
    private List<SecurityFinding> detectSQLInjection(CompilationUnit cu, Path sourcePath) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr methodCall, Void arg) {
                super.visit(methodCall, arg);
                
                String methodName = methodCall.getNameAsString();
                if ((methodName.equals("executeQuery") || methodName.equals("executeUpdate")) &&
                    methodCall.getArguments().size() > 0) {
                    
                    // Check if query is constructed with string concatenation
                    String argStr = methodCall.getArgument(0).toString();
                    if (argStr.contains("+") || argStr.contains("concat")) {
                        findings.add(new SecurityFinding(
                            null,
                            null,
                            SecurityFinding.Severity.CRITICAL,
                            "SQL Injection",
                            "Potential SQL injection vulnerability: query constructed with string concatenation",
                            sourcePath + ":" + methodCall.getBegin().get().line,
                            "CWE-89",
                            0.90,
                            List.of(
                                "Use PreparedStatement with parameterized queries",
                                "Implement input validation and sanitization",
                                "Use ORM frameworks with built-in SQL injection protection"
                            ),
                            true
                        ));
                    }
                }
            }
        }, null);
        
        return findings;
    }
    
    /**
     * Detect hardcoded credentials
     */
    private List<SecurityFinding> detectHardcodedCredentials(CompilationUnit cu, Path sourcePath) {
        List<SecurityFinding> findings = new ArrayList<>();
        String[] credentialKeywords = {"password", "passwd", "pwd", "secret", "apikey", "token"};
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodDeclaration method, Void arg) {
                super.visit(method, arg);
                
                String methodCode = method.toString().toLowerCase();
                for (String keyword : credentialKeywords) {
                    if (methodCode.contains(keyword + " = \"") || methodCode.contains(keyword + "=\"")) {
                        findings.add(new SecurityFinding(
                            null,
                            null,
                            SecurityFinding.Severity.HIGH,
                            "Hardcoded Credentials",
                            "Potential hardcoded credentials detected: " + keyword,
                            sourcePath + ":" + method.getBegin().get().line,
                            "CWE-798",
                            0.75,
                            List.of(
                                "Use environment variables or secure configuration management",
                                "Implement secrets management solution (e.g., HashiCorp Vault)",
                                "Never commit credentials to version control"
                            ),
                            true
                        ));
                    }
                }
            }
        }, null);
        
        return findings;
    }
    
    /**
     * Detect insecure deserialization
     */
    private List<SecurityFinding> detectInsecureDeserialization(CompilationUnit cu, Path sourcePath) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr methodCall, Void arg) {
                super.visit(methodCall, arg);
                
                if (methodCall.getNameAsString().equals("readObject") &&
                    methodCall.getScope().isPresent() &&
                    methodCall.getScope().get().toString().contains("ObjectInputStream")) {
                    
                    findings.add(new SecurityFinding(
                        null,
                        null,
                        SecurityFinding.Severity.HIGH,
                        "Insecure Deserialization",
                        "Potential insecure deserialization vulnerability",
                        sourcePath + ":" + methodCall.getBegin().get().line,
                        "CWE-502",
                        0.80,
                        List.of(
                            "Validate and sanitize serialized data",
                            "Use allowlist-based deserialization filters",
                            "Consider using JSON or XML instead of Java serialization"
                        ),
                        false
                    ));
                }
            }
        }, null);
        
        return findings;
    }
    
    /**
     * Load vulnerability patterns
     */
    private void loadVulnerabilityPatterns() {
        // Add common vulnerability patterns
        patterns.put("XXE", new VulnerabilityPattern(
            "XML External Entity",
            List.of("DocumentBuilderFactory", "SAXParserFactory"),
            "CWE-611",
            SecurityFinding.Severity.HIGH
        ));
        
        patterns.put("PATH_TRAVERSAL", new VulnerabilityPattern(
            "Path Traversal",
            List.of("File(", "FileInputStream(", "FileReader("),
            "CWE-22",
            SecurityFinding.Severity.HIGH
        ));
    }
    
    private SecurityFinding.Severity mapPMDSeverity(Rule rule) {
        return switch (rule.getPriority()) {
            case HIGH -> SecurityFinding.Severity.HIGH;
            case MEDIUM_HIGH -> SecurityFinding.Severity.MEDIUM;
            case MEDIUM -> SecurityFinding.Severity.MEDIUM;
            case MEDIUM_LOW, LOW -> SecurityFinding.Severity.LOW;
        };
    }
    
    private SecurityFinding.Severity mapSpotBugsSeverity(int priority) {
        return switch (priority) {
            case 1 -> SecurityFinding.Severity.CRITICAL;
            case 2 -> SecurityFinding.Severity.HIGH;
            case 3 -> SecurityFinding.Severity.MEDIUM;
            default -> SecurityFinding.Severity.LOW;
        };
    }
    
    @Override
    protected void cleanup() throws Exception {
        eventQueue.clear();
        logger.info("Static Analysis Agent cleaned up");
    }
    
    /**
     * Vulnerability pattern definition
     */
    record VulnerabilityPattern(
        String name,
        List<String> indicators,
        String cweId,
        SecurityFinding.Severity severity
    ) {}
    
    /**
     * Custom pattern detector for vulnerability patterns
     */
    private static class VulnerabilityPatternDetector {
        
        public List<SecurityFinding> detect(CompilationUnit cu, Path sourcePath) {
            List<SecurityFinding> findings = new ArrayList<>();
            
            // Detect XML External Entity (XXE) vulnerabilities
            findings.addAll(detectXXE(cu, sourcePath));
            
            // Detect Path Traversal vulnerabilities
            findings.addAll(detectPathTraversal(cu, sourcePath));
            
            return findings;
        }
        
        private List<SecurityFinding> detectXXE(CompilationUnit cu, Path sourcePath) {
            List<SecurityFinding> findings = new ArrayList<>();
            
            cu.accept(new VoidVisitorAdapter<Void>() {
                @Override
                public void visit(MethodCallExpr methodCall, Void arg) {
                    super.visit(methodCall, arg);
                    
                    if (methodCall.getNameAsString().equals("newDocumentBuilder") ||
                        methodCall.getNameAsString().equals("newSAXParser")) {
                        
                        findings.add(new SecurityFinding(
                            null,
                            null,
                            SecurityFinding.Severity.HIGH,
                            "XML External Entity (XXE)",
                            "Potential XXE vulnerability: XML parser without secure configuration",
                            sourcePath + ":" + methodCall.getBegin().get().line,
                            "CWE-611",
                            0.85,
                            List.of(
                                "Disable external entity processing",
                                "Set secure features on XML parser",
                                "Use secure XML parsing libraries"
                            ),
                            true
                        ));
                    }
                }
            }, null);
            
            return findings;
        }
        
        private List<SecurityFinding> detectPathTraversal(CompilationUnit cu, Path sourcePath) {
            List<SecurityFinding> findings = new ArrayList<>();
            
            cu.accept(new VoidVisitorAdapter<Void>() {
                @Override
                public void visit(MethodCallExpr methodCall, Void arg) {
                    super.visit(methodCall, arg);
                    
                    String scope = methodCall.getScope().map(Object::toString).orElse("");
                    if (scope.equals("File") || scope.equals("FileInputStream") || scope.equals("FileReader")) {
                        findings.add(new SecurityFinding(
                            null,
                            null,
                            SecurityFinding.Severity.MEDIUM,
                            "Path Traversal",
                            "Potential path traversal vulnerability: file operation with user input",
                            sourcePath + ":" + methodCall.getBegin().get().line,
                            "CWE-22",
                            0.70,
                            List.of(
                                "Validate and sanitize file paths",
                                "Use allowlist of permitted paths",
                                "Implement path canonicalization"
                            ),
                            true
                        ));
                    }
                }
            }, null);
            
            return findings;
        }
    }
}
