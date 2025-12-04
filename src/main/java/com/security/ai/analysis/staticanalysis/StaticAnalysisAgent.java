package com.security.ai.analysis.staticanalysis;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
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
import net.sourceforge.pmd.PMD;
import net.sourceforge.pmd.Rule;
import net.sourceforge.pmd.Report;
import net.sourceforge.pmd.RuleViolation;
import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.RuleSetFactory;
import net.sourceforge.pmd.renderers.Renderer;
import net.sourceforge.pmd.util.datasource.DataSource;
import net.sourceforge.pmd.util.datasource.FileDataSource;

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
            // Temporarily disabled PMD due to Saxon XPath library conflict with Java 25
            // findings.addAll(analyzeWithPMD(sourcePath));
            // SpotBugs requires compiled classes
            // findings.addAll(analyzeWithSpotBugs(sourcePath));
            
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
        
        // Log the source code being analyzed
        String sourceCode = Files.readString(sourcePath);
        logger.info("AST - Analyzing {} bytes of code: {}", 
            sourceCode.length(), 
            sourceCode.length() > 300 ? sourceCode.substring(0, 300) + "..." : sourceCode);
        
        ParseResult<CompilationUnit> parseResult = javaParser.parse(sourcePath);
        
        logger.info("AST - Parse successful: {}, result present: {}", 
            parseResult.isSuccessful(), 
            parseResult.getResult().isPresent());
        
        if (parseResult.isSuccessful() && parseResult.getResult().isPresent()) {
            CompilationUnit cu = parseResult.getResult().get();
            
            logger.info("AST - CompilationUnit types count: {}", cu.getTypes().size());
            
            // Detect SQL injection vulnerabilities
            List<SecurityFinding> sqlFindings = detectSQLInjection(cu, sourcePath);
            logger.info("AST - SQL injection findings: {}", sqlFindings.size());
            findings.addAll(sqlFindings);
            
            // Detect hardcoded credentials
            List<SecurityFinding> credFindings = detectHardcodedCredentials(cu, sourcePath);
            logger.info("AST - Hardcoded credentials findings: {}", credFindings.size());
            findings.addAll(credFindings);
            
            // Detect insecure deserialization
            findings.addAll(detectInsecureDeserialization(cu, sourcePath));
            
            // Detect command injection
            List<SecurityFinding> cmdFindings = detectCommandInjection(cu, sourcePath);
            logger.info("AST - Command injection findings: {}", cmdFindings.size());
            findings.addAll(cmdFindings);
            
            // Detect XSS vulnerabilities
            List<SecurityFinding> xssFindings = detectXSS(cu, sourcePath);
            logger.info("AST - XSS findings: {}", xssFindings.size());
            findings.addAll(xssFindings);
            
            // Detect XXE vulnerabilities
            List<SecurityFinding> xxeFindings = detectXXEInjection(cu, sourcePath);
            logger.info("AST - XXE findings: {}", xxeFindings.size());
            findings.addAll(xxeFindings);
            
            // Detect insecure cryptography
            List<SecurityFinding> cryptoFindings = detectInsecureCryptography(cu, sourcePath);
            logger.info("AST - Insecure crypto findings: {}", cryptoFindings.size());
            findings.addAll(cryptoFindings);
            
            // Detect insecure network
            List<SecurityFinding> networkFindings = detectInsecureNetwork(cu, sourcePath);
            logger.info("AST - Insecure network findings: {}", networkFindings.size());
            findings.addAll(networkFindings);
            
            // Custom pattern detection
            findings.addAll(patternDetector.detect(cu, sourcePath));
        } else {
            logger.warn("AST - Parse failed or no result");
            if (!parseResult.isSuccessful()) {
                parseResult.getProblems().forEach(problem -> 
                    logger.warn("AST - Parse problem: {}", problem.getMessage()));
            }
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
            config.setRuleSets("rulesets/java/quickstart.xml");
            
            RuleSetFactory ruleSetFactory = new RuleSetFactory();
            RuleContext ctx = new RuleContext();
            Report report = new Report();
            ctx.setReport(report);
            
            List<DataSource> files = Arrays.asList(new FileDataSource(sourcePath.toFile()));
            PMD.processFiles(config, ruleSetFactory, files, ctx, Arrays.asList(new Renderer[0]));
            
            for (RuleViolation violation : report) {
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
        } catch (Exception e) {
            logger.debug("PMD analysis skipped: {}", e.getMessage());
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
        
        // Detect SQL queries with string concatenation
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(VariableDeclarator var, Void arg) {
                super.visit(var, arg);
                
                if (var.getInitializer().isPresent()) {
                    String varName = var.getNameAsString().toLowerCase();
                    String initValue = var.getInitializer().get().toString();
                    
                    // Check if it's a SQL query (contains SQL keywords) with concatenation
                    if ((varName.contains("query") || varName.contains("sql")) &&
                        (initValue.toUpperCase().contains("SELECT") || 
                         initValue.toUpperCase().contains("INSERT") ||
                         initValue.toUpperCase().contains("UPDATE") ||
                         initValue.toUpperCase().contains("DELETE")) &&
                        initValue.contains("+")) {
                        
                        findings.add(new SecurityFinding(
                            null,
                            null,
                            SecurityFinding.Severity.CRITICAL,
                            "SQL Injection",
                            "SQL query constructed with string concatenation - vulnerable to SQL injection",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-89",
                            0.95,
                            List.of(
                                "Use PreparedStatement with parameterized queries instead of string concatenation",
                                "Never concatenate user input directly into SQL queries",
                                "Consider using an ORM framework with built-in SQL injection protection"
                            ),
                            true
                        ));
                    }
                }
            }
            
            @Override
            public void visit(MethodCallExpr methodCall, Void arg) {
                super.visit(methodCall, arg);
                
                String methodName = methodCall.getNameAsString();
                if ((methodName.equals("executeQuery") || methodName.equals("executeUpdate") || 
                     methodName.equals("execute")) && methodCall.getArguments().size() > 0) {
                    
                    // Check if query is constructed with string concatenation
                    String argStr = methodCall.getArgument(0).toString();
                    if (argStr.contains("+") || argStr.contains("concat")) {
                        findings.add(new SecurityFinding(
                            null,
                            null,
                            SecurityFinding.Severity.CRITICAL,
                            "SQL Injection",
                            "SQL execution with concatenated query - critical SQL injection vulnerability",
                            sourcePath + ":" + methodCall.getBegin().get().line,
                            "CWE-89",
                            0.98,
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
        String[] credentialKeywords = {"password", "passwd", "pwd", "secret", "apikey", "api_key", "token", "key", "credential", "auth"};
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(VariableDeclarator var, Void arg) {
                super.visit(var, arg);
                
                String varName = var.getNameAsString().toLowerCase();
                
                // Check if variable name suggests it's a credential
                for (String keyword : credentialKeywords) {
                    if (varName.contains(keyword) && var.getInitializer().isPresent()) {
                        String initValue = var.getInitializer().get().toString();
                        // Check if it's a hardcoded string literal (not empty, not a method call)
                        if (initValue.startsWith("\"") && initValue.length() > 3 && 
                            !initValue.contains("()") && !initValue.equals("\"\"")) {
                            
                            findings.add(new SecurityFinding(
                                null,
                                null,
                                SecurityFinding.Severity.HIGH,
                                "Hardcoded Credentials",
                                "Hardcoded credential found: " + varName + " = " + 
                                    (initValue.length() > 30 ? initValue.substring(0, 27) + "..." : initValue),
                                sourcePath + ":" + var.getBegin().get().line,
                                "CWE-798",
                                0.90,
                                List.of(
                                    "Store credentials in environment variables or secure vaults",
                                    "Use configuration management systems",
                                    "Never commit credentials to source control",
                                    "Consider using secrets management services"
                                ),
                                true
                            ));
                        }
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
            public void visit(VariableDeclarator var, Void arg) {
                super.visit(var, arg);
                
                if (var.getInitializer().isPresent()) {
                    String initValue = var.getInitializer().get().toString();
                    String varType = var.getType().toString();
                    
                    // Detect ObjectInputStream creation
                    if (varType.contains("ObjectInputStream") || initValue.contains("new ObjectInputStream")) {
                        findings.add(new SecurityFinding(
                            null,
                            null,
                            SecurityFinding.Severity.HIGH,
                            "Insecure Deserialization",
                            "ObjectInputStream usage detected - potential deserialization vulnerability",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-502",
                            0.85,
                            List.of(
                                "Validate object types before deserialization",
                                "Use allowlist of acceptable classes",
                                "Avoid deserializing untrusted data"
                            ),
                            true
                        ));
                    }
                    
                    // Detect XMLDecoder usage
                    if (varType.contains("XMLDecoder") || initValue.contains("new XMLDecoder")) {
                        findings.add(new SecurityFinding(
                            null,
                            null,
                            SecurityFinding.Severity.CRITICAL,
                            "Insecure Deserialization",
                            "XMLDecoder usage detected - critical deserialization vulnerability",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-502",
                            0.95,
                            List.of(
                                "Avoid using XMLDecoder for untrusted data",
                                "Use safer alternatives like JAXB or Jackson"
                            ),
                            true
                        ));
                    }
                }
            }
            
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
     * Detect command injection vulnerabilities
     */
    private List<SecurityFinding> detectCommandInjection(CompilationUnit cu, Path sourcePath) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr methodCall, Void arg) {
                super.visit(methodCall, arg);
                
                String methodName = methodCall.getNameAsString();
                
                // Detect Runtime.exec() with concatenation
                if (methodName.equals("exec") && methodCall.getArguments().size() > 0) {
                    String argStr = methodCall.getArgument(0).toString();
                    if (argStr.contains("+") || argStr.contains("concat")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.CRITICAL,
                            "Command Injection",
                            "Command execution with string concatenation - critical command injection vulnerability",
                            sourcePath + ":" + methodCall.getBegin().get().line,
                            "CWE-78",
                            0.98,
                            List.of(
                                "Never concatenate user input into shell commands",
                                "Use parameterized command execution with ProcessBuilder",
                                "Implement strict input validation and allowlisting",
                                "Avoid shell execution when possible"
                            ),
                            true
                        ));
                    }
                }
                
                // Detect ScriptEngine.eval() - code execution
                if (methodName.equals("eval")) {
                    findings.add(new SecurityFinding(
                        null, null,
                        SecurityFinding.Severity.CRITICAL,
                        "Code Injection",
                        "Dynamic code execution detected - can execute arbitrary code",
                        sourcePath + ":" + methodCall.getBegin().get().line,
                        "CWE-94",
                        0.95,
                        List.of(
                            "Avoid dynamic code execution with user input",
                            "Use safer alternatives or sandboxing",
                            "Implement strict input validation"
                        ),
                        true
                    ));
                }
            }
            
            @Override
            public void visit(VariableDeclarator var, Void arg) {
                super.visit(var, arg);
                
                if (var.getInitializer().isPresent()) {
                    String initValue = var.getInitializer().get().toString();
                    String varType = var.getType().toString();
                    
                    // Detect ProcessBuilder with concatenation
                    if (varType.contains("ProcessBuilder") && initValue.contains("+")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.HIGH,
                            "Command Injection",
                            "ProcessBuilder with string concatenation - potential command injection",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-78",
                            0.85,
                            List.of(
                                "Use ProcessBuilder with separate arguments",
                                "Validate and sanitize all inputs",
                                "Avoid shell invocation"
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
     * Detect Cross-Site Scripting (XSS) vulnerabilities
     */
    private List<SecurityFinding> detectXSS(CompilationUnit cu, Path sourcePath) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr methodCall, Void arg) {
                super.visit(methodCall, arg);
                
                String methodName = methodCall.getNameAsString();
                
                // Detect PrintWriter.println() with concatenation (reflected XSS)
                if ((methodName.equals("println") || methodName.equals("print") || methodName.equals("write")) 
                    && methodCall.getArguments().size() > 0) {
                    String argStr = methodCall.getArgument(0).toString();
                    if (argStr.contains("+") && (argStr.contains("<") || argStr.contains("html") || argStr.contains("script"))) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.CRITICAL,
                            "Cross-Site Scripting (XSS)",
                            "HTML output with unsanitized user input - XSS vulnerability",
                            sourcePath + ":" + methodCall.getBegin().get().line,
                            "CWE-79",
                            0.90,
                            List.of(
                                "Encode all user input before outputting to HTML",
                                "Use OWASP Java Encoder or similar libraries",
                                "Implement Content Security Policy (CSP)",
                                "Never trust user input in HTML context"
                            ),
                            true
                        ));
                    }
                }
                
                // Detect innerHTML or similar DOM manipulation
                if (methodName.equals("innerHTML") || methodName.equals("innerText")) {
                    findings.add(new SecurityFinding(
                        null, null,
                        SecurityFinding.Severity.HIGH,
                        "DOM-based XSS",
                        "Direct DOM manipulation - potential DOM-based XSS",
                        sourcePath + ":" + methodCall.getBegin().get().line,
                        "CWE-79",
                        0.75,
                        List.of(
                            "Sanitize all data before inserting into DOM",
                            "Use textContent instead of innerHTML when possible",
                            "Implement proper output encoding"
                        ),
                        true
                    ));
                }
            }
            
            @Override
            public void visit(VariableDeclarator var, Void arg) {
                super.visit(var, arg);
                
                if (var.getInitializer().isPresent()) {
                    String initValue = var.getInitializer().get().toString();
                    
                    // Detect HTML strings with concatenation
                    if ((initValue.contains("<html") || initValue.contains("<div") || 
                         initValue.contains("<script") || initValue.contains("<a href")) && 
                        initValue.contains("+")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.HIGH,
                            "Cross-Site Scripting (XSS)",
                            "HTML string constructed with concatenation - potential XSS",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-79",
                            0.85,
                            List.of(
                                "Use template engines with auto-escaping",
                                "Encode all user data before inserting into HTML",
                                "Avoid building HTML with string concatenation"
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
     * Detect XML External Entity (XXE) injection vulnerabilities
     */
    private List<SecurityFinding> detectXXEInjection(CompilationUnit cu, Path sourcePath) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(VariableDeclarator var, Void arg) {
                super.visit(var, arg);
                
                if (var.getInitializer().isPresent()) {
                    String varType = var.getType().toString();
                    String initValue = var.getInitializer().get().toString();
                    
                    // Detect unsafe XML parsers
                    if (varType.contains("DocumentBuilderFactory") || initValue.contains("DocumentBuilderFactory.newInstance")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.HIGH,
                            "XML External Entity (XXE) Injection",
                            "DocumentBuilderFactory without secure configuration - XXE vulnerability",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-611",
                            0.90,
                            List.of(
                                "Disable external entity processing: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
                                "Disable DOCTYPE declarations",
                                "Use secure XML parsing libraries"
                            ),
                            true
                        ));
                    }
                    
                    if (varType.contains("SAXParserFactory") || initValue.contains("SAXParserFactory.newInstance")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.HIGH,
                            "XML External Entity (XXE) Injection",
                            "SAXParserFactory without secure configuration - XXE vulnerability",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-611",
                            0.90,
                            List.of(
                                "Disable external entity processing",
                                "Set secure features on parser factory",
                                "Use JAXB or other secure alternatives"
                            ),
                            true
                        ));
                    }
                    
                    if (varType.contains("XMLReader") || initValue.contains("XMLReader")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.HIGH,
                            "XML External Entity (XXE) Injection",
                            "XMLReader without secure configuration - XXE vulnerability",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-611",
                            0.85,
                            List.of(
                                "Configure XMLReader with secure features",
                                "Disable external entity resolution"
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
     * Detect insecure cryptography vulnerabilities
     */
    private List<SecurityFinding> detectInsecureCryptography(CompilationUnit cu, Path sourcePath) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr methodCall, Void arg) {
                super.visit(methodCall, arg);
                
                String methodName = methodCall.getNameAsString();
                
                // Detect weak hash algorithms
                if (methodName.equals("getInstance") && methodCall.getArguments().size() > 0) {
                    String algorithm = methodCall.getArgument(0).toString().replace("\"", "").toUpperCase();
                    
                    if (algorithm.equals("MD5") || algorithm.equals("MD2")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.CRITICAL,
                            "Weak Cryptographic Hash",
                            "MD5 hash algorithm is cryptographically broken",
                            sourcePath + ":" + methodCall.getBegin().get().line,
                            "CWE-327",
                            0.95,
                            List.of(
                                "Use SHA-256 or SHA-3 for hashing",
                                "For passwords, use bcrypt, scrypt, or Argon2",
                                "MD5 is vulnerable to collision attacks"
                            ),
                            true
                        ));
                    }
                    
                    if (algorithm.equals("SHA1") || algorithm.equals("SHA-1")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.HIGH,
                            "Weak Cryptographic Hash",
                            "SHA-1 hash algorithm is deprecated and weak",
                            sourcePath + ":" + methodCall.getBegin().get().line,
                            "CWE-327",
                            0.90,
                            List.of(
                                "Use SHA-256, SHA-384, or SHA-512 instead",
                                "SHA-1 is vulnerable to collision attacks"
                            ),
                            true
                        ));
                    }
                    
                    if (algorithm.equals("DES")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.CRITICAL,
                            "Weak Encryption Algorithm",
                            "DES encryption is cryptographically broken",
                            sourcePath + ":" + methodCall.getBegin().get().line,
                            "CWE-327",
                            0.98,
                            List.of(
                                "Use AES-256 encryption instead",
                                "DES has 56-bit key and is easily brute-forced",
                                "Never use DES in production"
                            ),
                            true
                        ));
                    }
                    
                    // Detect ECB mode
                    if (algorithm.contains("ECB")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.HIGH,
                            "Insecure Cipher Mode",
                            "ECB mode is insecure - reveals patterns in encrypted data",
                            sourcePath + ":" + methodCall.getBegin().get().line,
                            "CWE-327",
                            0.90,
                            List.of(
                                "Use GCM or CBC mode instead of ECB",
                                "ECB does not provide semantic security",
                                "Use authenticated encryption (AES-GCM)"
                            ),
                            true
                        ));
                    }
                }
                
                // Detect weak random number generator
                if (methodCall.getScope().isPresent() && 
                    methodCall.getScope().get().toString().equals("Random") &&
                    (methodName.equals("nextInt") || methodName.equals("nextLong"))) {
                    findings.add(new SecurityFinding(
                        null, null,
                        SecurityFinding.Severity.HIGH,
                        "Weak Random Number Generator",
                        "java.util.Random is not cryptographically secure",
                        sourcePath + ":" + methodCall.getBegin().get().line,
                        "CWE-338",
                        0.85,
                        List.of(
                            "Use SecureRandom instead of Random",
                            "java.util.Random is predictable",
                            "Use SecureRandom for security-sensitive operations"
                        ),
                        true
                    ));
                }
            }
            
            @Override
            public void visit(VariableDeclarator var, Void arg) {
                super.visit(var, arg);
                
                if (var.getInitializer().isPresent()) {
                    String varType = var.getType().toString();
                    String initValue = var.getInitializer().get().toString();
                    
                    // Detect weak Random instantiation
                    if (varType.contains("Random") && !varType.contains("SecureRandom") && 
                        initValue.contains("new Random")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.MEDIUM,
                            "Weak Random Number Generator",
                            "Using java.util.Random - not cryptographically secure",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-338",
                            0.80,
                            List.of(
                                "Use SecureRandom for cryptographic operations",
                                "Random is predictable and unsuitable for security"
                            ),
                            false
                        ));
                    }
                }
            }
        }, null);
        
        return findings;
    }
    
    /**
     * Detect insecure network communication vulnerabilities
     */
    private List<SecurityFinding> detectInsecureNetwork(CompilationUnit cu, Path sourcePath) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodDeclaration method, Void arg) {
                super.visit(method, arg);
                
                String methodCode = method.toString();
                
                // Detect trust all certificates
                if (methodCode.contains("X509TrustManager") && 
                    (methodCode.contains("checkClientTrusted") || methodCode.contains("checkServerTrusted")) &&
                    methodCode.contains("{}")) {
                    findings.add(new SecurityFinding(
                        null, null,
                        SecurityFinding.Severity.CRITICAL,
                        "Insecure SSL/TLS Configuration",
                        "Accepting all SSL certificates - defeats SSL/TLS security",
                        sourcePath + ":" + method.getBegin().get().line,
                        "CWE-295",
                        0.98,
                        List.of(
                            "Never disable certificate validation",
                            "Use proper certificate validation",
                            "This enables man-in-the-middle attacks"
                        ),
                        true
                    ));
                }
                
                // Detect disabled hostname verification
                if (methodCode.contains("HostnameVerifier") && methodCode.contains("return true")) {
                    findings.add(new SecurityFinding(
                        null, null,
                        SecurityFinding.Severity.HIGH,
                        "Insecure SSL/TLS Configuration",
                        "Hostname verification disabled - vulnerable to MITM attacks",
                        sourcePath + ":" + method.getBegin().get().line,
                        "CWE-297",
                        0.95,
                        List.of(
                            "Enable hostname verification",
                            "Validate SSL certificate hostnames",
                            "Disabling verification allows MITM attacks"
                        ),
                        true
                    ));
                }
            }
            
            @Override
            public void visit(VariableDeclarator var, Void arg) {
                super.visit(var, arg);
                
                if (var.getInitializer().isPresent()) {
                    String varType = var.getType().toString();
                    String initValue = var.getInitializer().get().toString();
                    
                    // Detect HTTP instead of HTTPS
                    if (varType.contains("URL") && initValue.contains("\"http://") && !initValue.contains("localhost")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.CRITICAL,
                            "Insecure Network Communication",
                            "Using HTTP instead of HTTPS - data transmitted in cleartext",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-319",
                            0.95,
                            List.of(
                                "Always use HTTPS for sensitive data",
                                "HTTP traffic can be intercepted and modified",
                                "Implement TLS/SSL for all network communication"
                            ),
                            true
                        ));
                    }
                    
                    // Detect weak TLS version
                    if (initValue.contains("TLSv1\"") || initValue.contains("SSLv3") || initValue.contains("SSL\"")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.HIGH,
                            "Weak TLS Version",
                            "Using outdated TLS/SSL version - vulnerable to attacks",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-327",
                            0.90,
                            List.of(
                                "Use TLS 1.2 or TLS 1.3",
                                "TLS 1.0/1.1 and SSL are deprecated",
                                "Update to modern cryptographic protocols"
                            ),
                            true
                        ));
                    }
                    
                    // Detect plain Socket instead of SSLSocket
                    if (varType.equals("Socket") && initValue.contains("new Socket")) {
                        findings.add(new SecurityFinding(
                            null, null,
                            SecurityFinding.Severity.MEDIUM,
                            "Unencrypted Socket Communication",
                            "Using plain Socket without encryption",
                            sourcePath + ":" + var.getBegin().get().line,
                            "CWE-319",
                            0.75,
                            List.of(
                                "Use SSLSocket for encrypted communication",
                                "Plain sockets transmit data in cleartext",
                                "Implement TLS for socket communication"
                            ),
                            false
                        ));
                    }
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
        int priority = rule.getPriority().getPriority();
        if (priority <= 1) {
            return SecurityFinding.Severity.HIGH;
        } else if (priority == 2) {
            return SecurityFinding.Severity.MEDIUM;
        } else if (priority == 3) {
            return SecurityFinding.Severity.MEDIUM;
        } else {
            return SecurityFinding.Severity.LOW;
        }
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
    
    /**
     * Generate fixed code for a vulnerability using simple string replacement
     * @param originalCode The vulnerable code
     * @param finding The security finding
     * @return Fixed code or null if cannot fix
     */
    public String generateFix(String originalCode, SecurityAgent.SecurityFinding finding) {
        if (originalCode == null || finding == null) {
            logger.error("generateFix called with null: code={}, finding={}", originalCode != null, finding != null);
            return null;
        }
        
        try {
            String[] lines = originalCode.split("\\n");
            int lineNum = extractLineNumber(finding.location());
            
            logger.info("generateFix: category={}, lineNum={}, totalLines={}, location={}", 
                finding.category(), lineNum, lines.length, finding.location());
            
            if (lineNum <= 0 || lineNum > lines.length) {
                logger.error("Invalid line number: {} (total lines: {})", lineNum, lines.length);
                return null;
            }
            
            String category = finding.category();
            String targetLine = lines[lineNum - 1];
            String fixedLine = targetLine;
            
            logger.info("generateFix: targetLine=[{}]", targetLine);
            
            // Apply fixes based on category
            switch (category) {
                case "SQL Injection":
                    logger.info("SQL Injection case - checking line: {}", targetLine);
                    if (targetLine.contains("+") && (targetLine.contains("SELECT") || targetLine.contains("INSERT") || 
                        targetLine.contains("UPDATE") || targetLine.contains("DELETE"))) {
                        // Replace concatenation with PreparedStatement comment
                        fixedLine = targetLine + " // TODO: Use PreparedStatement with ? placeholder";
                        logger.info("SQL Injection fix applied: {}", fixedLine);
                    } else {
                        logger.warn("SQL Injection line did not match pattern. Contains +: {}, Contains SELECT: {}", 
                            targetLine.contains("+"), targetLine.contains("SELECT"));
                    }
                    break;
                    
                case "Hardcoded Credentials":
                    logger.info("Hardcoded Credentials case - checking line: {}", targetLine);
                    if (targetLine.contains("=") && targetLine.contains("\"")) {
                        // Simple fix: add comment to use environment variable
                        fixedLine = targetLine + " // SECURITY: Use System.getenv() or secure vault instead";
                        logger.info("Hardcoded Credentials fix applied");
                    } else {
                        logger.warn("Hardcoded Credentials line did not match pattern");
                    }
                    break;
                    
                case "Insecure Deserialization":
                    logger.info("Insecure Deserialization case - checking line: {}", targetLine);
                    if (targetLine.contains("ObjectInputStream") || targetLine.contains("XMLDecoder")) {
                        fixedLine = targetLine + " // SECURITY: Use JSON serialization (Jackson/Gson) instead";
                        logger.info("Insecure Deserialization fix applied");
                    } else {
                        logger.warn("Insecure Deserialization line did not match pattern");
                    }
                    break;
                    
                case "Path Traversal":
                    logger.info("Path Traversal case - checking line: {}", targetLine);
                    if (targetLine.contains("new File") && targetLine.contains("+")) {
                        fixedLine = targetLine + " // SECURITY: Validate and normalize path with Paths.get().normalize()";
                        logger.info("Path Traversal fix applied");
                    } else {
                        logger.warn("Path Traversal line did not match pattern");
                    }
                    break;
                    
                case "Command Injection":
                    logger.info("Command Injection case - checking line: {}", targetLine);
                    if (targetLine.contains("Runtime.getRuntime().exec") || targetLine.contains("ProcessBuilder")) {
                        fixedLine = targetLine + " // SECURITY: Use ProcessBuilder with String[] args, validate input";
                        logger.info("Command Injection fix applied");
                    } else {
                        logger.warn("Command Injection line did not match pattern");
                    }
                    break;
                    
                case "Cross-Site Scripting (XSS)":
                    logger.info("XSS case - checking line: {}", targetLine);
                    if (targetLine.contains("println") || targetLine.contains("print") || targetLine.contains("write")) {
                        fixedLine = targetLine + " // SECURITY: Use StringEscapeUtils.escapeHtml4() to encode output";
                        logger.info("XSS fix applied");
                    } else {
                        logger.warn("XSS line did not match pattern");
                    }
                    break;
                    
                case "XXE Injection":
                    logger.info("XXE case - checking line: {}", targetLine);
                    if (targetLine.contains("DocumentBuilderFactory") || targetLine.contains("SAXParserFactory") || targetLine.contains("XMLReader")) {
                        fixedLine = targetLine + " // SECURITY: Set XMLConstants.FEATURE_SECURE_PROCESSING and disable external entities";
                        logger.info("XXE fix applied");
                    } else {
                        logger.warn("XXE line did not match pattern");
                    }
                    break;
                    
                case "Insecure Cryptography":
                    logger.info("Insecure Cryptography case - checking line: {}", targetLine);
                    if (targetLine.contains("MD5") || targetLine.contains("MD2")) {
                        fixedLine = targetLine.replace("MD5", "SHA-256").replace("MD2", "SHA-256");
                        logger.info("Insecure Cryptography fix applied (MD5/MD2 -> SHA-256)");
                    } else if (targetLine.contains("DES") && !targetLine.contains("AES")) {
                        fixedLine = targetLine.replace("DES", "AES/GCM/NoPadding");
                        logger.info("Insecure Cryptography fix applied (DES -> AES)");
                    } else if (targetLine.contains("new Random()")) {
                        fixedLine = targetLine.replace("new Random()", "new SecureRandom()");
                        logger.info("Insecure Cryptography fix applied (Random -> SecureRandom)");
                    } else if (targetLine.contains("ECB")) {
                        fixedLine = targetLine.replace("ECB", "GCM");
                        logger.info("Insecure Cryptography fix applied (ECB -> GCM)");
                    } else {
                        fixedLine = targetLine + " // SECURITY: Use strong cryptography (SHA-256, AES/GCM, SecureRandom)";
                        logger.info("Insecure Cryptography generic fix applied");
                    }
                    break;
                    
                case "Insecure Network Protocol":
                case "Insecure Network Configuration":
                case "Insecure Network Communication":
                case "Weak TLS/SSL Protocol":
                case "Insecure SSL/TLS Configuration":
                    logger.info("Network/SSL/TLS case - checking line: {}", targetLine);
                    if (targetLine.contains("\"http://")) {
                        fixedLine = targetLine.replace("http://", "https://");
                        logger.info("Network fix applied (http -> https)");
                    } else if (targetLine.contains("TLSv1\"") || targetLine.contains("SSLv")) {
                        fixedLine = targetLine.replaceAll("(TLSv1|SSLv[0-9])", "TLSv1.3");
                        logger.info("Network fix applied (TLS version upgrade)");
                    } else if (targetLine.contains("new Socket")) {
                        fixedLine = targetLine + " // SECURITY: Use SSLSocketFactory.getDefault().createSocket()";
                        logger.info("Network fix applied (Socket -> SSLSocket recommendation)");
                    } else if (targetLine.contains("setHostnameVerifier") || targetLine.contains("ALLOW_ALL")) {
                        fixedLine = "        // SECURITY FIX: Hostname verification MUST be enabled\n" + 
                                   "        // " + targetLine.trim() + " // REMOVED - Use default verifier\n" +
                                   "        // connection.setHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());";
                        logger.info("Network fix applied (hostname verification)");
                    } else if (targetLine.contains("TrustManager")) {
                        fixedLine = targetLine + " // SECURITY: Do NOT use custom TrustManagers that accept all certificates";
                        logger.info("Network fix applied (TrustManager warning)");
                    } else if (targetLine.contains("checkServerTrusted") || targetLine.contains("checkClientTrusted")) {
                        fixedLine = "        // SECURITY FIX: Use default SSL certificate validation\n" +
                                   "        // " + targetLine.trim() + " // REMOVED - implement proper validation";
                        logger.info("Network fix applied (certificate validation)");
                    } else {
                        // Generic SSL/TLS fix comment
                        fixedLine = targetLine + " // SECURITY: Enable proper SSL/TLS validation";
                        logger.info("Network generic fix applied");
                    }
                    break;
                    
                default:
                    logger.warn("No fix handler for category: {}", category);
                    break;
            }
            
            // Rebuild code with fixed line
            if (!fixedLine.equals(targetLine)) {
                lines[lineNum - 1] = fixedLine;
                return String.join("\n", lines);
            }
            
            return null; // No fix applied
            
        } catch (Exception e) {
            logger.error("Failed to generate fix: {}", e.getMessage());
            return null;
        }
    }
    
    private int extractLineNumber(String location) {
        if (location == null) return 0;
        try {
            // Location format: "file.java:3" or "path/to/file.java:3"
            // Extract the number AFTER the last colon
            if (location.contains(":")) {
                String[] parts = location.split(":");
                // Get the last part (line number)
                String lineNumStr = parts[parts.length - 1].trim();
                return Integer.parseInt(lineNumStr);
            }
            // Fallback: try to find any number
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\d+");
            java.util.regex.Matcher matcher = pattern.matcher(location);
            if (matcher.find()) {
                return Integer.parseInt(matcher.group());
            }
        } catch (Exception e) {
            logger.error("Failed to extract line number from location: {}", location, e);
        }
        return 0;
    }
    
    private String extractVariableName(String line) {
        try {
            // Extract variable name from declaration like: String password = "..."
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\b(\\w+)\\s*=");
            java.util.regex.Matcher matcher = pattern.matcher(line);
            if (matcher.find()) {
                return matcher.group(1);
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }
}
