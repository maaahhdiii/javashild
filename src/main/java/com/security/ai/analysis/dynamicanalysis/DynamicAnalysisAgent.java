package com.security.ai.analysis.dynamicanalysis;

import com.security.ai.agent.AbstractSecurityAgent;
import com.security.ai.agent.SecurityAgent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Dynamic analysis agent that monitors runtime behavior and detects
 * vulnerabilities through bytecode instrumentation and runtime monitoring.
 */
public class DynamicAnalysisAgent extends AbstractSecurityAgent {
    
    private final RuntimeMonitor runtimeMonitor;
    private final Map<String, BehaviorPattern> suspiciousPatterns = new ConcurrentHashMap<>();
    private final List<RuntimeViolation> detectedViolations = new CopyOnWriteArrayList<>();
    
    public DynamicAnalysisAgent() {
        super();
        this.runtimeMonitor = new RuntimeMonitor(this);
        initializeSuspiciousPatterns();
    }
    
    @Override
    public AgentType getType() {
        return AgentType.DYNAMIC_ANALYZER;
    }
    
    @Override
    protected void initialize() throws Exception {
        logger.info("Initializing Dynamic Analysis Agent");
        runtimeMonitor.start();
        status.set(AgentStatus.RUNNING);
    }
    
    @Override
    protected void runAgentLoop() throws Exception {
        while (status.get() == AgentStatus.RUNNING) {
            try {
                Thread.sleep(5000); // Check every 5 seconds
                analyzeRuntimeBehavior();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    @Override
    protected List<SecurityFinding> performAnalysis(SecurityEvent event) throws Exception {
        List<SecurityFinding> findings = new ArrayList<>();
        
        if (event.type() == SecurityEvent.EventType.RUNTIME_BEHAVIOR) {
            findings.addAll(analyzeRuntimeEvent(event));
        } else if (event.type() == SecurityEvent.EventType.API_CALL) {
            findings.addAll(analyzeAPICall(event));
        } else if (event.type() == SecurityEvent.EventType.FILE_ACCESS) {
            findings.addAll(analyzeFileAccess(event));
        } else if (event.type() == SecurityEvent.EventType.NETWORK_REQUEST) {
            findings.addAll(analyzeNetworkRequest(event));
        }
        
        return findings;
    }
    
    /**
     * Analyze runtime behavior patterns
     */
    private void analyzeRuntimeBehavior() {
        for (RuntimeViolation violation : detectedViolations) {
            if (!violation.reported()) {
                logger.warn("Runtime violation detected: {} at {}", 
                    violation.type(), violation.location());
                violation.markReported();
            }
        }
    }
    
    /**
     * Analyze runtime event for vulnerabilities
     */
    private List<SecurityFinding> analyzeRuntimeEvent(SecurityEvent event) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        if (event.payload() instanceof RuntimeBehavior behavior) {
            // Check for suspicious patterns
            for (BehaviorPattern pattern : suspiciousPatterns.values()) {
                if (pattern.matches(behavior)) {
                    findings.add(new SecurityFinding(
                        null,
                        null,
                        pattern.severity(),
                        "Runtime Behavior: " + pattern.name(),
                        pattern.description(),
                        behavior.location(),
                        null,
                        pattern.confidence(),
                        pattern.recommendations(),
                        pattern.blockable()
                    ));
                }
            }
        }
        
        return findings;
    }
    
    /**
     * Analyze API calls for security issues
     */
    private List<SecurityFinding> analyzeAPICall(SecurityEvent event) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        if (event.payload() instanceof APICallInfo apiCall) {
            // Detect reflection abuse
            if (apiCall.className().contains("java.lang.reflect")) {
                findings.add(new SecurityFinding(
                    null,
                    null,
                    SecurityFinding.Severity.MEDIUM,
                    "Reflection Usage",
                    "Reflection API usage detected: " + apiCall.methodName(),
                    apiCall.stackTrace(),
                    "CWE-470",
                    0.70,
                    List.of(
                        "Review reflection usage for security implications",
                        "Implement strict access controls",
                        "Consider alternatives to reflection"
                    ),
                    false
                ));
            }
            
            // Detect unsafe native code calls
            if (apiCall.methodName().startsWith("native") || apiCall.className().contains("sun.misc.Unsafe")) {
                findings.add(new SecurityFinding(
                    null,
                    null,
                    SecurityFinding.Severity.HIGH,
                    "Unsafe Native Code",
                    "Unsafe native code execution detected",
                    apiCall.stackTrace(),
                    "CWE-242",
                    0.85,
                    List.of(
                        "Avoid using sun.misc.Unsafe",
                        "Use safe Java alternatives",
                        "Implement strict sandboxing"
                    ),
                    true
                ));
            }
        }
        
        return findings;
    }
    
    /**
     * Analyze file access for security violations
     */
    private List<SecurityFinding> analyzeFileAccess(SecurityEvent event) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        if (event.payload() instanceof FileAccessInfo fileAccess) {
            // Detect access to sensitive files
            String[] sensitivePaths = {"/etc/passwd", "/etc/shadow", "C:\\Windows\\System32", 
                                       ".ssh", ".aws", ".env"};
            
            for (String sensitivePath : sensitivePaths) {
                if (fileAccess.path().contains(sensitivePath)) {
                    findings.add(new SecurityFinding(
                        null,
                        null,
                        SecurityFinding.Severity.CRITICAL,
                        "Sensitive File Access",
                        "Access to sensitive file detected: " + fileAccess.path(),
                        fileAccess.stackTrace(),
                        "CWE-200",
                        0.95,
                        List.of(
                            "Block access to sensitive system files",
                            "Implement strict file access controls",
                            "Audit all file access operations"
                        ),
                        true
                    ));
                }
            }
            
            // Detect suspicious file operations
            if (fileAccess.operation().equals("DELETE") || fileAccess.operation().equals("WRITE")) {
                findings.add(new SecurityFinding(
                    null,
                    null,
                    SecurityFinding.Severity.MEDIUM,
                    "File Modification",
                    "File modification operation detected: " + fileAccess.operation(),
                    fileAccess.path(),
                    null,
                    0.60,
                    List.of(
                        "Review file modification operations",
                        "Implement audit logging",
                        "Validate file paths"
                    ),
                    false
                ));
            }
        }
        
        return findings;
    }
    
    /**
     * Analyze network requests for security issues
     */
    private List<SecurityFinding> analyzeNetworkRequest(SecurityEvent event) {
        List<SecurityFinding> findings = new ArrayList<>();
        
        if (event.payload() instanceof NetworkRequestInfo netRequest) {
            // Detect non-HTTPS connections to external hosts
            if (!netRequest.protocol().equalsIgnoreCase("https") && 
                !netRequest.host().contains("localhost") &&
                !netRequest.host().startsWith("127.0.0.1")) {
                
                findings.add(new SecurityFinding(
                    null,
                    null,
                    SecurityFinding.Severity.HIGH,
                    "Insecure Network Connection",
                    "Unencrypted network connection to: " + netRequest.host(),
                    netRequest.stackTrace(),
                    "CWE-319",
                    0.90,
                    List.of(
                        "Use HTTPS for all external connections",
                        "Implement TLS/SSL encryption",
                        "Validate SSL certificates"
                    ),
                    true
                ));
            }
            
            // Detect connections to suspicious domains
            String[] suspiciousTLDs = {".ru", ".cn", ".tk", ".ml"};
            for (String tld : suspiciousTLDs) {
                if (netRequest.host().endsWith(tld)) {
                    findings.add(new SecurityFinding(
                        null,
                        null,
                        SecurityFinding.Severity.CRITICAL,
                        "Suspicious Network Connection",
                        "Connection to suspicious domain: " + netRequest.host(),
                        netRequest.stackTrace(),
                        null,
                        0.75,
                        List.of(
                            "Block connection to suspicious domains",
                            "Implement domain allowlist",
                            "Review network traffic logs"
                        ),
                        true
                    ));
                }
            }
        }
        
        return findings;
    }
    
    /**
     * Initialize suspicious behavior patterns
     */
    private void initializeSuspiciousPatterns() {
        suspiciousPatterns.put("EXCESSIVE_MEMORY", new BehaviorPattern(
            "Excessive Memory Allocation",
            "Potential memory exhaustion attack",
            SecurityFinding.Severity.HIGH,
            0.80,
            List.of("Implement memory limits", "Monitor memory usage", "Detect DoS attempts"),
            true
        ));
        
        suspiciousPatterns.put("RAPID_FILE_ACCESS", new BehaviorPattern(
            "Rapid File Access",
            "Unusual file access pattern detected",
            SecurityFinding.Severity.MEDIUM,
            0.70,
            List.of("Rate limit file operations", "Implement access controls", "Monitor file access"),
            false
        ));
        
        suspiciousPatterns.put("PRIVILEGE_ESCALATION", new BehaviorPattern(
            "Privilege Escalation Attempt",
            "Attempt to gain elevated privileges detected",
            SecurityFinding.Severity.CRITICAL,
            0.95,
            List.of("Block privilege escalation", "Implement strict access controls", "Alert security team"),
            true
        ));
    }
    
    @Override
    protected void cleanup() throws Exception {
        runtimeMonitor.stop();
        detectedViolations.clear();
        logger.info("Dynamic Analysis Agent cleaned up");
    }
    
    /**
     * Runtime monitor for behavior tracking
     */
    private static class RuntimeMonitor {
        private final DynamicAnalysisAgent agent;
        private Thread monitorThread;
        private volatile boolean running = false;
        
        RuntimeMonitor(DynamicAnalysisAgent agent) {
            this.agent = agent;
        }
        
        void start() {
            running = true;
            monitorThread = Thread.ofVirtual().start(() -> {
                while (running) {
                    try {
                        Thread.sleep(1000);
                        collectRuntimeMetrics();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            });
        }
        
        void stop() {
            running = false;
            if (monitorThread != null) {
                monitorThread.interrupt();
            }
        }
        
        private void collectRuntimeMetrics() {
            // Collect runtime metrics like memory usage, thread count, etc.
            Runtime runtime = Runtime.getRuntime();
            long usedMemory = runtime.totalMemory() - runtime.freeMemory();
            long maxMemory = runtime.maxMemory();
            
            if (usedMemory > maxMemory * 0.9) {
                agent.detectedViolations.add(new RuntimeViolation(
                    "MEMORY_THRESHOLD",
                    "Memory usage exceeds 90%",
                    "JVM Memory Monitor"
                ));
            }
        }
    }
    
    /**
     * Runtime behavior information
     */
    record RuntimeBehavior(
        String behaviorType,
        String description,
        String location,
        Map<String, Object> metrics
    ) {}
    
    /**
     * API call information
     */
    record APICallInfo(
        String className,
        String methodName,
        Object[] arguments,
        String stackTrace
    ) {}
    
    /**
     * File access information
     */
    record FileAccessInfo(
        String path,
        String operation,
        String stackTrace
    ) {}
    
    /**
     * Network request information
     */
    public record NetworkRequestInfo(
        String protocol,
        String host,
        int port,
        String path,
        String stackTrace
    ) {}
    
    /**
     * Behavior pattern for detection
     */
    record BehaviorPattern(
        String name,
        String description,
        SecurityFinding.Severity severity,
        double confidence,
        List<String> recommendations,
        boolean blockable
    ) {
        boolean matches(RuntimeBehavior behavior) {
            return behavior.behaviorType().equals(name);
        }
    }
    
    /**
     * Runtime violation record
     */
    static class RuntimeViolation {
        private final String type;
        private final String description;
        private final String location;
        private boolean reported = false;
        
        RuntimeViolation(String type, String description, String location) {
            this.type = type;
            this.description = description;
            this.location = location;
        }
        
        String type() { return type; }
        String description() { return description; }
        String location() { return location; }
        boolean reported() { return reported; }
        void markReported() { this.reported = true; }
    }
}
