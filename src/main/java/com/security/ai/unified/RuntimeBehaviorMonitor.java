package com.security.ai.unified;

import com.security.ai.agent.SecurityAgent;
import com.security.ai.analysis.dynamicanalysis.DynamicAnalysisAgent.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Runtime Behavior Monitor - Tracks application behavior at runtime
 * 
 * Monitors:
 * - Network requests (HTTP/HTTPS, SSL/TLS)
 * - File system access
 * - API calls (Reflection, Native code)
 * - Database connections
 * - Memory usage
 * - Thread activity
 */
public class RuntimeBehaviorMonitor {
    
    private static final Logger logger = LoggerFactory.getLogger(RuntimeBehaviorMonitor.class);
    
    private final ConcurrentHashMap<String, List<SecurityAgent.SecurityFinding>> runtimeFindings = new ConcurrentHashMap<>();
    private volatile boolean running = false;
    
    public void start() {
        running = true;
        logger.info("✓ Runtime Behavior Monitor started");
    }
    
    public void stop() {
        running = false;
        logger.info("Runtime Behavior Monitor stopped");
    }
    
    public List<SecurityAgent.SecurityFinding> analyzeNetworkRequest(NetworkRequestInfo netInfo) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        // Detect non-HTTPS connections
        if (!netInfo.protocol().equalsIgnoreCase("https") && 
            !netInfo.host().contains("localhost") &&
            !netInfo.host().startsWith("127.0.0.1")) {
            
            String fixCode = "// Auto-fix: Enforce HTTPS connections\n" +
                "// Before: URL url = new URL(\"http://example.com\");\n" +
                "// After:\n" +
                "URL url = new URL(\"https://example.com\");\n\n" +
                "// Or configure HttpClient to only allow HTTPS:\n" +
                "HttpClient client = HttpClient.newBuilder()\n" +
                "    .version(HttpClient.Version.HTTP_2)\n" +
                "    .sslContext(SSLContext.getDefault())\n" +
                "    .build();";
            
            findings.add(new SecurityAgent.SecurityFinding(
                null, null,
                SecurityAgent.SecurityFinding.Severity.HIGH,
                "Insecure Network Connection",
                "Unencrypted network connection to: " + netInfo.host(),
                netInfo.stackTrace(),
                "CWE-319",
                0.90,
                List.of("Use HTTPS for all external connections"),
                false,
                "DYNAMIC: Runtime Monitor",
                fixCode
            ));
        }
        
        // Detect suspicious domains
        String[] suspiciousTlds = {".ru", ".cn", ".tk", ".ml", ".ga"};
        for (String tld : suspiciousTlds) {
            if (netInfo.host().endsWith(tld)) {
                findings.add(new SecurityAgent.SecurityFinding(
                    null, null,
                    SecurityAgent.SecurityFinding.Severity.MEDIUM,
                    "Suspicious Network Destination",
                    "Connection to potentially risky domain: " + netInfo.host(),
                    netInfo.stackTrace(),
                    null,
                    0.70,
                    List.of("Review domain reputation"),
                    false,
                    "DYNAMIC: Runtime Monitor",
                    null
                ));
            }
        }
        
        return findings;
    }
    
    public List<SecurityAgent.SecurityFinding> analyzeFileAccess(FileAccessInfo fileInfo) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        // Detect access to sensitive files
        String[] sensitivePaths = {"/etc/passwd", "/etc/shadow", "C:\\Windows\\System32", 
                                   ".ssh", ".aws", ".env"};
        
        for (String sensitivePath : sensitivePaths) {
            if (fileInfo.path().contains(sensitivePath)) {
                String fixCode = "// Auto-fix: Implement file access control\n" +
                    "Path requestedPath = Paths.get(userInput).normalize();\n" +
                    "Path allowedDir = Paths.get(\"/safe/directory\");\n" +
                    "if (!requestedPath.startsWith(allowedDir)) {\n" +
                    "    throw new SecurityException(\"Access denied to: \" + requestedPath);\n" +
                    "}\n" +
                    "// Only allow access within safe directory";
                
                findings.add(new SecurityAgent.SecurityFinding(
                    null, null,
                    SecurityAgent.SecurityFinding.Severity.CRITICAL,
                    "Sensitive File Access",
                    "Access to sensitive file detected: " + fileInfo.path(),
                    fileInfo.stackTrace(),
                    "CWE-200",
                    0.95,
                    List.of("Block access to sensitive system files"),
                    true,
                    "DYNAMIC: Runtime Monitor",
                    fixCode
                ));
            }
        }
        
        return findings;
    }
    
    public List<SecurityAgent.SecurityFinding> analyzeAPICall(APICallInfo apiInfo) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        // Detect reflection abuse
        if (apiInfo.className().contains("java.lang.reflect")) {
            findings.add(new SecurityAgent.SecurityFinding(
                null, null,
                SecurityAgent.SecurityFinding.Severity.MEDIUM,
                "Reflection Usage",
                "Reflection API usage detected: " + apiInfo.methodName(),
                apiInfo.stackTrace(),
                "CWE-470",
                0.70,
                List.of("Review reflection usage for security implications"),
                false,
                "DYNAMIC: Runtime Monitor",
                null
            ));
        }
        
        // Detect unsafe native code calls
        if (apiInfo.className().contains("sun.misc.Unsafe")) {
            String fixCode = "// Auto-fix: Avoid sun.misc.Unsafe\n" +
                "// sun.misc.Unsafe is dangerous and should not be used\n" +
                "// Use standard Java APIs instead:\n\n" +
                "// For memory operations, use ByteBuffer:\n" +
                "ByteBuffer buffer = ByteBuffer.allocateDirect(1024);\n\n" +
                "// For atomics, use java.util.concurrent.atomic:\n" +
                "AtomicInteger counter = new AtomicInteger();";
            
            findings.add(new SecurityAgent.SecurityFinding(
                null, null,
                SecurityAgent.SecurityFinding.Severity.HIGH,
                "Unsafe Native Code",
                "Unsafe native code execution detected",
                apiInfo.stackTrace(),
                "CWE-242",
                0.85,
                List.of("Avoid using sun.misc.Unsafe"),
                true,
                "DYNAMIC: Runtime Monitor",
                fixCode
            ));
        }
        
        return findings;
    }
    
    // Inner classes for runtime event information
    public record FileAccessInfo(String path, String operation, String stackTrace) {}
    public record APICallInfo(String className, String methodName, String stackTrace) {}
}
