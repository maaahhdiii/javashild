package com.security.ai.unified;

import com.security.ai.agent.SecurityAgent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PMD-Style Analyzer - Security-focused pattern detection
 * 
 * Performs pattern-based static analysis for security issues:
 * - Security vulnerabilities (SQL injection, XSS, hardcoded secrets)
 * - Code quality issues
 * - Best practice violations
 * - Dangerous API usage
 * 
 * Note: Uses custom pattern matching to avoid PMD's Saxon XPath version conflicts
 */
public class PMDAnalyzer {
    
    private static final Logger logger = LoggerFactory.getLogger(PMDAnalyzer.class);
    
    // Security patterns to detect
    private static final List<SecurityPattern> SECURITY_PATTERNS = new ArrayList<>();
    
    static {
        // SQL Injection patterns
        SECURITY_PATTERNS.add(new SecurityPattern(
            "SQL_INJECTION",
            Pattern.compile("(executeQuery|executeUpdate|execute)\\s*\\(\\s*[^)]*\\+", Pattern.CASE_INSENSITIVE),
            SecurityAgent.SecurityFinding.Severity.CRITICAL,
            "SQL Injection: Query built with string concatenation",
            "CWE-89",
            List.of("Use PreparedStatement with parameterized queries", "Never concatenate user input into SQL"),
            "PreparedStatement pstmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\npstmt.setString(1, userId);"
        ));
        
        // Hardcoded passwords
        SECURITY_PATTERNS.add(new SecurityPattern(
            "HARDCODED_PASSWORD",
            Pattern.compile("(password|passwd|pwd|secret|apikey|api_key)\\s*=\\s*\"[^\"]{3,}\"", Pattern.CASE_INSENSITIVE),
            SecurityAgent.SecurityFinding.Severity.HIGH,
            "Hardcoded credential detected - passwords should not be in source code",
            "CWE-798",
            List.of("Use environment variables", "Use a secrets manager", "Use configuration files outside source control"),
            "String password = System.getenv(\"DB_PASSWORD\");\nif (password == null) throw new IllegalStateException(\"DB_PASSWORD not set\");"
        ));
        
        // Weak random number generator
        SECURITY_PATTERNS.add(new SecurityPattern(
            "WEAK_RANDOM",
            Pattern.compile("new\\s+Random\\s*\\(|Math\\.random\\s*\\("),
            SecurityAgent.SecurityFinding.Severity.MEDIUM,
            "Weak random number generator - not suitable for security purposes",
            "CWE-330",
            List.of("Use SecureRandom for cryptographic purposes", "java.util.Random is predictable"),
            "import java.security.SecureRandom;\nSecureRandom random = new SecureRandom();\nbyte[] bytes = new byte[16];\nrandom.nextBytes(bytes);"
        ));
        
        // Weak hashing algorithms
        SECURITY_PATTERNS.add(new SecurityPattern(
            "WEAK_HASH",
            Pattern.compile("MessageDigest\\.getInstance\\s*\\(\\s*\"(MD5|SHA-?1)\"\\s*\\)", Pattern.CASE_INSENSITIVE),
            SecurityAgent.SecurityFinding.Severity.MEDIUM,
            "Weak cryptographic hash algorithm - MD5 and SHA-1 are broken",
            "CWE-328",
            List.of("Use SHA-256 or SHA-3", "For passwords, use bcrypt, scrypt, or Argon2"),
            "MessageDigest md = MessageDigest.getInstance(\"SHA-256\");"
        ));
        
        // Weak encryption
        SECURITY_PATTERNS.add(new SecurityPattern(
            "WEAK_CRYPTO",
            Pattern.compile("Cipher\\.getInstance\\s*\\(\\s*\"(DES|DESede|RC2|RC4|Blowfish)(/|\")", Pattern.CASE_INSENSITIVE),
            SecurityAgent.SecurityFinding.Severity.HIGH,
            "Weak encryption algorithm detected",
            "CWE-327",
            List.of("Use AES-256-GCM", "Avoid DES, 3DES, RC4, Blowfish"),
            "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");"
        ));
        
        // ECB mode (insecure)
        SECURITY_PATTERNS.add(new SecurityPattern(
            "ECB_MODE",
            Pattern.compile("Cipher\\.getInstance\\s*\\(\\s*\"[^\"]+/ECB/"),
            SecurityAgent.SecurityFinding.Severity.HIGH,
            "ECB mode is insecure - identical plaintext blocks produce identical ciphertext",
            "CWE-327",
            List.of("Use CBC or GCM mode instead of ECB", "ECB mode leaks information about plaintext structure"),
            "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");"
        ));
        
        // Command injection
        SECURITY_PATTERNS.add(new SecurityPattern(
            "COMMAND_INJECTION",
            Pattern.compile("Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(\\s*[^)]*\\+"),
            SecurityAgent.SecurityFinding.Severity.CRITICAL,
            "Command injection vulnerability - command built with string concatenation",
            "CWE-78",
            List.of("Use ProcessBuilder with argument arrays", "Never concatenate user input into commands"),
            "ProcessBuilder pb = new ProcessBuilder(\"cmd\", \"/c\", command);\nProcess p = pb.start();"
        ));
        
        // Path traversal
        SECURITY_PATTERNS.add(new SecurityPattern(
            "PATH_TRAVERSAL",
            Pattern.compile("new\\s+(File|FileInputStream|FileOutputStream|FileReader|FileWriter)\\s*\\(\\s*[^)]*\\+"),
            SecurityAgent.SecurityFinding.Severity.HIGH,
            "Potential path traversal - file path built with concatenation",
            "CWE-22",
            List.of("Validate and canonicalize file paths", "Use Path.normalize() and check against base directory"),
            "Path base = Paths.get(\"/safe/dir\").toRealPath();\nPath target = base.resolve(userInput).normalize();\nif (!target.startsWith(base)) throw new SecurityException(\"Path traversal detected\");"
        ));
        
        // LDAP injection
        SECURITY_PATTERNS.add(new SecurityPattern(
            "LDAP_INJECTION",
            Pattern.compile("(search|lookup)\\s*\\(\\s*[^)]*\\+"),
            SecurityAgent.SecurityFinding.Severity.HIGH,
            "Potential LDAP injection - filter built with string concatenation",
            "CWE-90",
            List.of("Use parameterized LDAP queries", "Escape special LDAP characters"),
            "// Use LDAP encoding: String safeInput = LdapEncoder.filterEncode(userInput);"
        ));
        
        // Null cipher
        SECURITY_PATTERNS.add(new SecurityPattern(
            "NULL_CIPHER",
            Pattern.compile("NullCipher\\s*\\("),
            SecurityAgent.SecurityFinding.Severity.CRITICAL,
            "NullCipher provides no encryption - data is transmitted in plaintext",
            "CWE-327",
            List.of("Use a real cipher like AES/GCM", "NullCipher is for testing only"),
            "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");"
        ));
        
        // Trust all certificates
        SECURITY_PATTERNS.add(new SecurityPattern(
            "TRUST_ALL_CERTS",
            Pattern.compile("TrustAllCerts|TrustManager\\s*\\[\\]\\s*\\{|X509TrustManager.*return\\s+null", Pattern.DOTALL),
            SecurityAgent.SecurityFinding.Severity.CRITICAL,
            "Certificate validation disabled - vulnerable to MITM attacks",
            "CWE-295",
            List.of("Use default trust manager", "Never disable certificate validation in production"),
            "// Use default SSLContext:\nSSLContext ctx = SSLContext.getInstance(\"TLS\");\nctx.init(null, null, null);"
        ));
        
        // Disabled CSRF protection
        SECURITY_PATTERNS.add(new SecurityPattern(
            "CSRF_DISABLED",
            Pattern.compile("csrf\\(\\)\\.disable\\(\\)|csrfTokenRepository.*withHttpOnly.*false", Pattern.CASE_INSENSITIVE),
            SecurityAgent.SecurityFinding.Severity.HIGH,
            "CSRF protection is disabled",
            "CWE-352",
            List.of("Enable CSRF protection", "Use CSRF tokens for state-changing operations"),
            "// Enable CSRF: http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());"
        ));
        
        // Unvalidated redirect
        SECURITY_PATTERNS.add(new SecurityPattern(
            "OPEN_REDIRECT",
            Pattern.compile("(sendRedirect|redirect)\\s*\\(\\s*(request\\.getParameter|params\\.|input)"),
            SecurityAgent.SecurityFinding.Severity.MEDIUM,
            "Open redirect vulnerability - redirect URL from user input",
            "CWE-601",
            List.of("Validate redirect URLs against whitelist", "Use relative URLs for redirects"),
            "String url = request.getParameter(\"url\");\nif (ALLOWED_URLS.contains(url)) { response.sendRedirect(url); }"
        ));
        
        // Deserialization
        SECURITY_PATTERNS.add(new SecurityPattern(
            "DESERIALIZATION",
            Pattern.compile("new\\s+ObjectInputStream\\s*\\(|readObject\\s*\\(\\)"),
            SecurityAgent.SecurityFinding.Severity.CRITICAL,
            "Unsafe deserialization - can lead to remote code execution",
            "CWE-502",
            List.of("Use JSON or XML instead of Java serialization", "Implement look-ahead validation", "Use ObjectInputFilter (Java 9+)"),
            "// Use JSON:\nObjectMapper mapper = new ObjectMapper();\nMyClass obj = mapper.readValue(json, MyClass.class);"
        ));
        
        // Empty catch block
        SECURITY_PATTERNS.add(new SecurityPattern(
            "EMPTY_CATCH",
            Pattern.compile("catch\\s*\\([^)]+\\)\\s*\\{\\s*\\}"),
            SecurityAgent.SecurityFinding.Severity.LOW,
            "Empty catch block - exceptions are silently swallowed",
            "CWE-390",
            List.of("Log the exception", "Handle or re-throw exceptions appropriately"),
            "catch (Exception e) {\n    logger.error(\"Operation failed\", e);\n    throw new RuntimeException(\"Operation failed\", e);\n}"
        ));
        
        // System.exit() call
        SECURITY_PATTERNS.add(new SecurityPattern(
            "SYSTEM_EXIT",
            Pattern.compile("System\\.exit\\s*\\("),
            SecurityAgent.SecurityFinding.Severity.MEDIUM,
            "System.exit() call can cause denial of service",
            "CWE-382",
            List.of("Avoid System.exit() in library code", "Use exceptions for error handling"),
            "// Throw exception instead:\nthrow new RuntimeException(\"Fatal error occurred\");"
        ));
        
        // Logging sensitive data
        SECURITY_PATTERNS.add(new SecurityPattern(
            "LOG_SENSITIVE",
            Pattern.compile("(log|logger|LOG)\\.(info|debug|warn|error)\\s*\\([^)]*password|secret|token|key|credential", Pattern.CASE_INSENSITIVE),
            SecurityAgent.SecurityFinding.Severity.HIGH,
            "Sensitive data may be logged - passwords should never be logged",
            "CWE-532",
            List.of("Never log passwords or secrets", "Use placeholders like [REDACTED]"),
            "logger.info(\"User {} authenticated successfully\", username);  // Don't log password!"
        ));
    }
    
    public void initialize() {
        logger.info("Initializing PMD Analyzer...");
        logger.info("✓ PMD Analyzer initialized with {} security patterns", SECURITY_PATTERNS.size());
    }
    
    public List<SecurityAgent.SecurityFinding> analyze(Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            if (!Files.exists(sourcePath) || !sourcePath.toString().endsWith(".java")) {
                return findings;
            }
            
            logger.debug("PMD analyzing: {}", sourcePath);
            
            String sourceCode = Files.readString(sourcePath);
            String[] lines = sourceCode.split("\n");
            
            for (SecurityPattern pattern : SECURITY_PATTERNS) {
                Matcher matcher = pattern.pattern.matcher(sourceCode);
                while (matcher.find()) {
                    // Find line number
                    int lineNum = findLineNumber(sourceCode, matcher.start());
                    String matchedText = matcher.group();
                    if (matchedText.length() > 50) {
                        matchedText = matchedText.substring(0, 50) + "...";
                    }
                    
                    findings.add(new SecurityAgent.SecurityFinding(
                        UUID.randomUUID().toString(),
                        Instant.now(),
                        pattern.severity,
                        "PMD: " + pattern.name,
                        pattern.description + " [Match: " + matchedText + "]",
                        sourcePath.getFileName() + ":" + lineNum,
                        pattern.cweId,
                        0.85,
                        pattern.recommendations,
                        true,
                        "STATIC: PMD",
                        pattern.fixCode
                    ));
                }
            }
            
            logger.debug("PMD found {} violations in {}", findings.size(), sourcePath.getFileName());
            
        } catch (Exception e) {
            logger.debug("PMD analysis skipped for {} ({})", sourcePath.getFileName(), e.getMessage());
        }
        
        return findings;
    }
    
    private int findLineNumber(String source, int charIndex) {
        int line = 1;
        for (int i = 0; i < charIndex && i < source.length(); i++) {
            if (source.charAt(i) == '\n') {
                line++;
            }
        }
        return line;
    }
    
    /**
     * Security pattern definition for pattern-based analysis
     */
    private static class SecurityPattern {
        final String name;
        final Pattern pattern;
        final SecurityAgent.SecurityFinding.Severity severity;
        final String description;
        final String cweId;
        final List<String> recommendations;
        final String fixCode;
        
        SecurityPattern(String name, Pattern pattern, SecurityAgent.SecurityFinding.Severity severity,
                       String description, String cweId, List<String> recommendations, String fixCode) {
            this.name = name;
            this.pattern = pattern;
            this.severity = severity;
            this.description = description;
            this.cweId = cweId;
            this.recommendations = recommendations;
            this.fixCode = fixCode;
        }
    }
}
