package com.security.ai.unified;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.security.ai.agent.SecurityAgent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Custom AST Analyzer - Deep code analysis using JavaParser
 * 
 * Performs custom security-focused Abstract Syntax Tree analysis:
 * - SQL Injection patterns
 * - Hardcoded credentials
 * - Command Injection
 * - XSS vulnerabilities
 * - Insecure deserialization
 * - All 9 vulnerability types from original StaticAnalysisAgent
 */
public class CustomASTAnalyzer {
    
    private static final Logger logger = LoggerFactory.getLogger(CustomASTAnalyzer.class);
    
    private final JavaParser javaParser;
    
    public CustomASTAnalyzer() {
        this.javaParser = new JavaParser();
    }
    
    public void initialize() {
        logger.info("✓ Custom AST Analyzer initialized");
    }
    
    public List<SecurityAgent.SecurityFinding> analyze(Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            if (!Files.exists(sourcePath) || !sourcePath.toString().endsWith(".java")) {
                return findings;
            }
            
            logger.debug("Custom AST analyzing: {}", sourcePath);
            
            ParseResult<CompilationUnit> parseResult = javaParser.parse(sourcePath);
            
            if (parseResult.isSuccessful() && parseResult.getResult().isPresent()) {
                CompilationUnit cu = parseResult.getResult().get();
                
                // Detect all 9 vulnerability types
                findings.addAll(detectSQLInjection(cu, sourcePath));
                findings.addAll(detectHardcodedCredentials(cu, sourcePath));
                findings.addAll(detectCommandInjection(cu, sourcePath));
                findings.addAll(detectXSS(cu, sourcePath));
                findings.addAll(detectXXE(cu, sourcePath));
                findings.addAll(detectInsecureDeserialization(cu, sourcePath));
                findings.addAll(detectPathTraversal(cu, sourcePath));
                findings.addAll(detectInsecureCrypto(cu, sourcePath));
                findings.addAll(detectInsecureNetwork(cu, sourcePath));
                
                logger.debug("Custom AST found {} vulnerabilities in {}", findings.size(), sourcePath.getFileName());
            }
            
        } catch (Exception e) {
            logger.error("Custom AST analysis failed for {}", sourcePath, e);
        }
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> detectSQLInjection(CompilationUnit cu, Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodDeclaration method, Void arg) {
                super.visit(method, arg);
                
                // Check method body for SQL-related string operations
                method.getBody().ifPresent(body -> {
                    String bodyStr = body.toString().toLowerCase();
                    
                    // Check for SQL keywords with string concatenation
                    if ((bodyStr.contains("select") || bodyStr.contains("insert") || 
                         bodyStr.contains("update") || bodyStr.contains("delete") ||
                         bodyStr.contains("from users") || bodyStr.contains("where")) &&
                        (bodyStr.contains(" + ") || bodyStr.contains("concat"))) {
                        
                        // Check if it's user input concatenation (variable names suggest input)
                        if (bodyStr.contains("username") || bodyStr.contains("password") || 
                            bodyStr.contains("input") || bodyStr.contains("user") ||
                            bodyStr.contains("id") || bodyStr.contains("param")) {
                            
                            String fixCode = "// Auto-fix: Use PreparedStatement\n" +
                                "String sql = \"SELECT * FROM users WHERE username = ?\";\n" +
                                "PreparedStatement stmt = connection.prepareStatement(sql);\n" +
                                "stmt.setString(1, username);\n" +
                                "ResultSet rs = stmt.executeQuery();";
                            
                            findings.add(new SecurityAgent.SecurityFinding(
                                null, null,
                                SecurityAgent.SecurityFinding.Severity.CRITICAL,
                                "SQL Injection Vulnerability",
                                "SQL query built with user input concatenation detected. " +
                                "This allows attackers to inject malicious SQL code. " +
                                "Use PreparedStatement with parameterized queries instead.",
                                sourcePath.getFileName() + ":" + method.getBegin().map(b -> String.valueOf(b.line)).orElse("?"),
                                "CWE-89",
                                0.95,
                                List.of(
                                    "Use PreparedStatement with ? placeholders",
                                    "Never concatenate user input into SQL queries",
                                    "Use ORM frameworks like Hibernate with parameterized queries",
                                    "Validate and sanitize all user inputs"
                                ),
                                true,
                                "STATIC: CustomAST",
                                fixCode
                            ));
                        }
                    }
                });
            }
            
            @Override
            public void visit(MethodCallExpr methodCall, Void arg) {
                super.visit(methodCall, arg);
                
                String methodName = methodCall.getNameAsString();
                if ((methodName.equals("executeQuery") || methodName.equals("executeUpdate") ||
                     methodName.equals("execute") || methodName.equals("createStatement")) 
                    && methodCall.getArguments().size() > 0) {
                    
                    String argStr = methodCall.getArgument(0).toString();
                    if (argStr.contains("+") || argStr.contains("concat")) {
                        String fixCode = "// Auto-fix: Replace with PreparedStatement\n" +
                            "PreparedStatement pstmt = connection.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n" +
                            "pstmt.setString(1, userId);\n" +
                            "ResultSet rs = pstmt.executeQuery();";
                        
                        findings.add(new SecurityAgent.SecurityFinding(
                            null, null,
                            SecurityAgent.SecurityFinding.Severity.CRITICAL,
                            "SQL Injection via Method Call",
                            "SQL query with string concatenation passed to " + methodName + "(). " +
                            "This creates an injection vulnerability.",
                            sourcePath.getFileName() + ":" + methodCall.getBegin().map(b -> String.valueOf(b.line)).orElse("?"),
                            "CWE-89",
                            0.98,
                            List.of("Use PreparedStatement with parameterized queries"),
                            true,
                            "STATIC: CustomAST",
                            fixCode
                        ));
                    }
                }
            }
        }, null);
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> detectHardcodedCredentials(CompilationUnit cu, Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(VariableDeclarator var, Void arg) {
                super.visit(var, arg);
                
                String varName = var.getNameAsString().toLowerCase();
                if ((varName.contains("password") || varName.contains("secret") || 
                     varName.contains("apikey") || varName.contains("token")) &&
                    var.getInitializer().isPresent()) {
                    
                    String initValue = var.getInitializer().get().toString();
                    if (initValue.contains("\"") && initValue.length() > 5) {
                        String fixCode = "// Auto-fix: Use environment variables\\n" +
                            "// Before: String password = \\\"hardcoded123\\\";\\n" +
                            "// After:\\n" +
                            "String password = System.getenv(\\\"DB_PASSWORD\\\");\\n" +
                            "if (password == null) {\\n" +
                            "    throw new IllegalStateException(\\\"DB_PASSWORD environment variable not set\\\");\\n" +
                            "}";
                        
                        findings.add(new SecurityAgent.SecurityFinding(
                            null, null,
                            SecurityAgent.SecurityFinding.Severity.HIGH,
                            "Hardcoded Credentials",
                            "Hardcoded password/secret detected in variable: " + var.getNameAsString(),
                            sourcePath.getFileName() + ":" + var.getBegin().map(b -> String.valueOf(b.line)).orElse("?"),
                            "CWE-798",
                            0.90,
                            List.of("Use environment variables or secure credential stores", "Never hardcode passwords in source code"),
                            true,
                            "STATIC: CustomAST",
                            fixCode
                        ));
                    }
                }
            }
        }, null);
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> detectCommandInjection(CompilationUnit cu, Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr methodCall, Void arg) {
                super.visit(methodCall, arg);
                
                String methodName = methodCall.getNameAsString();
                if (methodName.equals("exec") && methodCall.getScope().isPresent()) {
                    String scopeStr = methodCall.getScope().get().toString();
                    if (scopeStr.contains("Runtime") && methodCall.getArguments().size() > 0) {
                        String argStr = methodCall.getArgument(0).toString();
                        if (argStr.contains("+") || argStr.contains("concat")) {
                            String fixCode = "// Auto-fix: Use ProcessBuilder for safe command execution\\n" +
                                "// Before: Runtime.getRuntime().exec(\\\"ls \\\" + userInput);\\n" +
                                "// After:\\n" +
                                "ProcessBuilder pb = new ProcessBuilder(\\\"ls\\\", userInput);\\n" +
                                "pb.redirectErrorStream(true);\\n" +
                                "Process process = pb.start();";
                            
                            findings.add(new SecurityAgent.SecurityFinding(
                                null, null,
                                SecurityAgent.SecurityFinding.Severity.CRITICAL,
                                "Command Injection",
                                "Runtime.exec() with concatenated command detected",
                                sourcePath.getFileName() + ":" + methodCall.getBegin().map(b -> String.valueOf(b.line)).orElse("?"),
                                "CWE-78",
                                0.95,
                                List.of("Use ProcessBuilder with argument list", "Never concatenate user input into commands"),
                                true,
                                "STATIC: CustomAST",
                                fixCode
                            ));
                        }
                    }
                }
            }
        }, null);
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> detectXSS(CompilationUnit cu, Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr methodCall, Void arg) {
                super.visit(methodCall, arg);
                
                String methodName = methodCall.getNameAsString();
                if ((methodName.equals("print") || methodName.equals("println") || 
                     methodName.equals("write") || methodName.contains("Html")) &&
                    methodCall.getArguments().size() > 0) {
                    
                    String argStr = methodCall.getArgument(0).toString();
                    if (argStr.contains("request.getParameter") || argStr.contains("input") ||
                        argStr.contains("user")) {
                        String fixCode = "// Auto-fix: Sanitize HTML output\n" +
                            "import org.apache.commons.text.StringEscapeUtils;\n\n" +
                            "// Before: out.println(request.getParameter(\"name\"));\n" +
                            "// After:\n" +
                            "String userInput = request.getParameter(\"name\");\n" +
                            "String safeOutput = StringEscapeUtils.escapeHtml4(userInput);\n" +
                            "out.println(safeOutput);";
                        
                        findings.add(new SecurityAgent.SecurityFinding(
                            null, null,
                            SecurityAgent.SecurityFinding.Severity.HIGH,
                            "Cross-Site Scripting (XSS)",
                            "User input output without sanitization detected",
                            sourcePath.getFileName() + ":" + methodCall.getBegin().map(b -> String.valueOf(b.line)).orElse("?"),
                            "CWE-79",
                            0.85,
                            List.of("Sanitize all user input before output", "Use HTML encoding libraries"),
                            true,
                            "STATIC: CustomAST",
                            fixCode
                        ));
                    }
                }
            }
        }, null);
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> detectXXE(CompilationUnit cu, Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr methodCall, Void arg) {
                super.visit(methodCall, arg);
                
                String methodName = methodCall.getNameAsString();
                
                // Detect DocumentBuilderFactory.newInstance() without secure configuration
                if ((methodName.equals("newInstance") || methodName.equals("newDocumentBuilder")) && 
                    methodCall.getScope().isPresent()) {
                    String scopeStr = methodCall.getScope().get().toString();
                    if (scopeStr.contains("DocumentBuilderFactory") || scopeStr.contains("SAXParserFactory")) {
                        String fixCode = "// Auto-fix: Disable XXE processing\n" +
                            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n" +
                            "dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n" +
                            "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
                            "dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
                            "dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n" +
                            "DocumentBuilder db = dbf.newDocumentBuilder();";
                        
                        findings.add(new SecurityAgent.SecurityFinding(
                            null, null,
                            SecurityAgent.SecurityFinding.Severity.HIGH,
                            "XML External Entity (XXE)",
                            "XML parser created without XXE protection. External entity processing is enabled by default, allowing XXE attacks.",
                            sourcePath.getFileName() + ":" + methodCall.getBegin().map(b -> String.valueOf(b.line)).orElse("?"),
                            "CWE-611",
                            0.90,
                            List.of("Disable external entity processing", "Use setFeature() to secure parser", "Set FEATURE_SECURE_PROCESSING to true"),
                            true,
                            "STATIC: CustomAST",
                            fixCode
                        ));
                    }
                }
                
                // Also detect parse() calls
                if (methodName.equals("parse") && methodCall.getScope().isPresent()) {
                    String scopeStr = methodCall.getScope().get().toString();
                    if (scopeStr.contains("DocumentBuilder") || scopeStr.contains("SAXParser")) {
                        String fixCode = "// Auto-fix: Disable XXE processing\n" +
                            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n" +
                            "dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n" +
                            "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" +
                            "dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" +
                            "dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n" +
                            "DocumentBuilder db = dbf.newDocumentBuilder();";
                        
                        findings.add(new SecurityAgent.SecurityFinding(
                            null, null,
                            SecurityAgent.SecurityFinding.Severity.HIGH,
                            "XML External Entity (XXE)",
                            "XML parser parsing content without XXE protection",
                            sourcePath.getFileName() + ":" + methodCall.getBegin().map(b -> String.valueOf(b.line)).orElse("?"),
                            "CWE-611",
                            0.85,
                            List.of("Disable external entity processing", "Use setFeature() to secure parser"),
                            true,
                            "STATIC: CustomAST",
                            fixCode
                        ));
                    }
                }
            }
        }, null);
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> detectInsecureDeserialization(CompilationUnit cu, Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(ObjectCreationExpr objCreation, Void arg) {
                super.visit(objCreation, arg);
                
                String typeName = objCreation.getTypeAsString();
                if (typeName.equals("ObjectInputStream")) {
                    String fixCode = "// Auto-fix: Use JSON instead of Java serialization\n" +
                        "import com.fasterxml.jackson.databind.ObjectMapper;\n\n" +
                        "// Before: ObjectInputStream ois = new ObjectInputStream(inputStream);\n" +
                        "// After:\n" +
                        "ObjectMapper mapper = new ObjectMapper();\n" +
                        "MyClass obj = mapper.readValue(inputStream, MyClass.class);";
                    
                    findings.add(new SecurityAgent.SecurityFinding(
                        null, null,
                        SecurityAgent.SecurityFinding.Severity.CRITICAL,
                        "Insecure Deserialization",
                        "ObjectInputStream usage detected - potential RCE vulnerability",
                        sourcePath.getFileName() + ":" + objCreation.getBegin().map(b -> String.valueOf(b.line)).orElse("?"),
                        "CWE-502",
                        0.90,
                        List.of("Use JSON or XML instead", "Implement input validation", "Use look-ahead deserializers"),
                        true,
                        "STATIC: CustomAST",
                        fixCode
                    ));
                }
            }
        }, null);
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> detectPathTraversal(CompilationUnit cu, Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(ObjectCreationExpr objCreation, Void arg) {
                super.visit(objCreation, arg);
                
                String typeName = objCreation.getTypeAsString();
                if ((typeName.equals("File") || typeName.equals("FileInputStream") || 
                     typeName.equals("FileOutputStream")) && objCreation.getArguments().size() > 0) {
                    
                    String argStr = objCreation.getArgument(0).toString();
                    if (argStr.contains("+") || argStr.contains("concat") || 
                        argStr.contains("request.getParameter") || argStr.contains("input")) {
                        String fixCode = "// Auto-fix: Validate and canonicalize file paths\n" +
                            "import java.nio.file.Paths;\n" +
                            "import java.io.IOException;\n\n" +
                            "// Before: File file = new File(\"/uploads/\" + userInput);\n" +
                            "// After:\n" +
                            "Path basePath = Paths.get(\"/uploads\").toRealPath();\n" +
                            "Path requestedPath = basePath.resolve(userInput).normalize();\n" +
                            "if (!requestedPath.startsWith(basePath)) {\n" +
                            "    throw new SecurityException(\"Path traversal attempt detected\");\n" +
                            "}\n" +
                            "File file = requestedPath.toFile();";
                        
                        findings.add(new SecurityAgent.SecurityFinding(
                            null, null,
                            SecurityAgent.SecurityFinding.Severity.HIGH,
                            "Path Traversal",
                            "File path with user input detected",
                            sourcePath.getFileName() + ":" + objCreation.getBegin().map(b -> String.valueOf(b.line)).orElse("?"),
                            "CWE-22",
                            0.85,
                            List.of("Validate file paths", "Use canonical paths", "Whitelist allowed files"),
                            true,
                            "STATIC: CustomAST",
                            fixCode
                        ));
                    }
                }
            }
        }, null);
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> detectInsecureCrypto(CompilationUnit cu, Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr methodCall, Void arg) {
                super.visit(methodCall, arg);
                
                String methodName = methodCall.getNameAsString();
                if (methodName.equals("getInstance") && methodCall.getArguments().size() > 0) {
                    String argStr = methodCall.getArgument(0).toString().toLowerCase();
                    if (argStr.contains("md5") || argStr.contains("sha1") || 
                        argStr.contains("des") || argStr.contains("\"rc4\"")) {
                        String fixCode = "// Auto-fix: Use strong cryptographic algorithms\n" +
                            "import javax.crypto.Cipher;\n" +
                            "import javax.crypto.spec.GCMParameterSpec;\n\n" +
                            "// Before: MessageDigest md = MessageDigest.getInstance(\"MD5\");\n" +
                            "// After (for hashing):\n" +
                            "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n\n" +
                            "// Before: Cipher cipher = Cipher.getInstance(\"DES\");\n" +
                            "// After (for encryption):\n" +
                            "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");";
                        
                        findings.add(new SecurityAgent.SecurityFinding(
                            null, null,
                            SecurityAgent.SecurityFinding.Severity.MEDIUM,
                            "Weak Cryptography",
                            "Weak cryptographic algorithm detected: " + argStr,
                            sourcePath.getFileName() + ":" + methodCall.getBegin().map(b -> String.valueOf(b.line)).orElse("?"),
                            "CWE-327",
                            0.80,
                            List.of("Use SHA-256 or SHA-3", "Use AES-256-GCM for encryption"),
                            true,
                            "STATIC: CustomAST",
                            fixCode
                        ));
                    }
                }
            }
        }, null);
        
        return findings;
    }
    
    private List<SecurityAgent.SecurityFinding> detectInsecureNetwork(CompilationUnit cu, Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(StringLiteralExpr strLiteral, Void arg) {
                super.visit(strLiteral, arg);
                
                String value = strLiteral.getValue().toLowerCase();
                if (value.startsWith("http://") && !value.contains("localhost") && !value.contains("127.0.0.1")) {
                    String fixCode = "// Auto-fix: Use HTTPS for secure communications\n" +
                        "// Before: String url = \"http://api.example.com/data\";\n" +
                        "// After:\n" +
                        "String url = \"https://api.example.com/data\";\n\n" +
                        "// For HttpClient:\n" +
                        "HttpClient client = HttpClient.newBuilder()\n" +
                        "    .version(HttpClient.Version.HTTP_2)\n" +
                        "    .build();";
                    
                    findings.add(new SecurityAgent.SecurityFinding(
                        null, null,
                        SecurityAgent.SecurityFinding.Severity.MEDIUM,
                        "Insecure HTTP Connection",
                        "HTTP (non-encrypted) URL detected: " + strLiteral.getValue(),
                        sourcePath.getFileName() + ":" + strLiteral.getBegin().map(b -> String.valueOf(b.line)).orElse("?"),
                        "CWE-319",
                        0.75,
                        List.of("Use HTTPS instead of HTTP", "Encrypt all network communications"),
                        true,
                        "STATIC: CustomAST",
                        fixCode
                    ));
                }
            }
        }, null);
        
        return findings;
    }
}
