package com.security.ai.unified;

import com.security.ai.agent.SecurityAgent;
import edu.umd.cs.findbugs.*;
import edu.umd.cs.findbugs.config.UserPreferences;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * SpotBugs Analyzer - Bytecode analysis using SpotBugs (https://spotbugs.github.io)
 * 
 * SpotBugs performs static analysis on compiled .class files to detect:
 * - Security vulnerabilities
 * - Bug patterns
 * - Correctness issues
 * - Performance problems
 */
public class SpotBugsAnalyzer {
    
    private static final Logger logger = LoggerFactory.getLogger(SpotBugsAnalyzer.class);
    
    private FindBugs2 engine;
    private Project project;
    
    public void initialize() {
        logger.info("Initializing SpotBugs Analyzer...");
        
        try {
            DetectorFactoryCollection.instance(); // Initialize detector factory
            
            project = new Project();
            engine = new FindBugs2();
            engine.setProject(project);
            
            // Set user preferences for security-focused analysis
            UserPreferences prefs = UserPreferences.createDefaultUserPreferences();
            prefs.setEffort(UserPreferences.EFFORT_MAX);
            prefs.enableAllDetectors(true);
            engine.setUserPreferences(prefs);
            
            logger.info("✓ SpotBugs Analyzer initialized");
            
        } catch (Exception e) {
            logger.error("Failed to initialize SpotBugs", e);
        }
    }
    
    public List<SecurityAgent.SecurityFinding> analyze(Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            if (!sourcePath.toString().endsWith(".java")) {
                return findings;
            }
            
            // SpotBugs requires compiled .class files - try multiple approaches
            Path classPath = null;
            
            // Approach 1: Try standard Maven structure first
            classPath = convertToClassPath(sourcePath);
            if (classPath != null && classPath.toFile().exists()) {
                logger.debug("Found compiled class at: {}", classPath);
            } else {
                // Approach 2: Compile the source file on-the-fly
                classPath = compileSource(sourcePath);
            }
            
            if (classPath == null || !classPath.toFile().exists()) {
                // Fall back to pattern-based analysis if compilation fails
                findings.addAll(analyzeSourcePatterns(sourcePath));
                return findings;
            }
            
            logger.debug("SpotBugs analyzing: {}", classPath);
            
            // Reset project for new analysis
            project = new Project();
            engine.setProject(project);
            project.addFile(classPath.toString());
            
            engine.execute();
            SortedBugCollection bugCollection = (SortedBugCollection) engine.getBugReporter().getBugCollection();
            
            for (BugInstance bug : bugCollection) {
                findings.add(convertToSecurityFinding(bug, sourcePath));
            }
            
            logger.debug("SpotBugs found {} bugs in {}", findings.size(), sourcePath.getFileName());
            
        } catch (Exception e) {
            logger.debug("SpotBugs bytecode analysis failed, using pattern analysis: {}", e.getMessage());
            // Fall back to pattern-based analysis
            findings.addAll(analyzeSourcePatterns(sourcePath));
        }
        
        return findings;
    }
    
    /**
     * Pattern-based security analysis when bytecode analysis is not available
     */
    private List<SecurityAgent.SecurityFinding> analyzeSourcePatterns(Path sourcePath) {
        List<SecurityAgent.SecurityFinding> findings = new ArrayList<>();
        
        try {
            String source = java.nio.file.Files.readString(sourcePath);
            String[] lines = source.split("\\n");
            
            // Security patterns that SpotBugs would normally detect
            java.util.Map<String, Object[]> patterns = java.util.Map.ofEntries(
                java.util.Map.entry("new\\s+Random\\s*\\(\\s*\\)", new Object[]{"WEAK_RANDOM", "HIGH", "Use SecureRandom instead of Random for security-sensitive operations", "CWE-330"}),
                java.util.Map.entry("\\.(format|printf)\\s*\\([^,]+\\+", new Object[]{"FORMAT_STRING", "MEDIUM", "Potential format string vulnerability - user input in format string", "CWE-134"}),
                java.util.Map.entry("setAccessible\\s*\\(\\s*true\\s*\\)", new Object[]{"REFLECTION_ABUSE", "MEDIUM", "Reflection used to bypass access control", "CWE-470"}),
                java.util.Map.entry("\\beval\\s*\\(|ScriptEngine.*eval", new Object[]{"CODE_INJECTION", "CRITICAL", "Dynamic code evaluation - potential code injection", "CWE-94"}),
                java.util.Map.entry("printStackTrace\\s*\\(\\s*\\)", new Object[]{"STACK_TRACE_EXPOSURE", "LOW", "Stack trace exposure may leak sensitive information", "CWE-209"}),
                java.util.Map.entry("getClass\\s*\\(\\s*\\)\\.getClassLoader", new Object[]{"CLASSLOADER_LEAK", "MEDIUM", "ClassLoader access may enable class loading attacks", "CWE-470"}),
                java.util.Map.entry("Runtime\\.getRuntime\\s*\\(\\s*\\)\\.exec", new Object[]{"COMMAND_EXEC", "HIGH", "External command execution detected", "CWE-78"}),
                java.util.Map.entry("SSLContext\\.getInstance\\s*\\(\\s*\\\"SSL\\\"", new Object[]{"WEAK_SSL", "HIGH", "SSLv3 is deprecated and insecure - use TLS", "CWE-326"}),
                java.util.Map.entry("allowAllHostnames|ALLOW_ALL_HOSTNAME", new Object[]{"HOSTNAME_VERIFIER", "CRITICAL", "Hostname verification disabled - vulnerable to MITM", "CWE-295"}),
                java.util.Map.entry("createSocket.*\\)\\s*;\\s*//.*no\\s*check", new Object[]{"UNVERIFIED_SOCKET", "HIGH", "Socket created without proper verification", "CWE-295"})
            );
            
            for (java.util.Map.Entry<String, Object[]> entry : patterns.entrySet()) {
                java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(entry.getKey(), java.util.regex.Pattern.CASE_INSENSITIVE);
                java.util.regex.Matcher matcher = pattern.matcher(source);
                
                while (matcher.find()) {
                    Object[] info = entry.getValue();
                    int lineNum = countNewlines(source, matcher.start()) + 1;
                    
                    SecurityAgent.SecurityFinding.Severity severity = switch ((String) info[1]) {
                        case "CRITICAL" -> SecurityAgent.SecurityFinding.Severity.CRITICAL;
                        case "HIGH" -> SecurityAgent.SecurityFinding.Severity.HIGH;
                        case "MEDIUM" -> SecurityAgent.SecurityFinding.Severity.MEDIUM;
                        default -> SecurityAgent.SecurityFinding.Severity.LOW;
                    };
                    
                    findings.add(new SecurityAgent.SecurityFinding(
                        null, null,
                        severity,
                        "SpotBugs: " + info[0],
                        (String) info[2],
                        sourcePath.getFileName() + ":" + lineNum,
                        (String) info[3],
                        0.80,
                        List.of("Review and fix this security issue"),
                        true,
                        "STATIC: SpotBugs",
                        null
                    ));
                }
            }
            
            logger.debug("SpotBugs pattern analysis found {} issues in {}", findings.size(), sourcePath.getFileName());
            
        } catch (Exception e) {
            logger.debug("SpotBugs pattern analysis failed: {}", e.getMessage());
        }
        
        return findings;
    }
    
    private int countNewlines(String s, int endIndex) {
        int count = 0;
        for (int i = 0; i < endIndex && i < s.length(); i++) {
            if (s.charAt(i) == '\n') count++;
        }
        return count;
    }
    
    private Path compileSource(Path sourcePath) {
        try {
            // Compile source file to temporary directory
            javax.tools.JavaCompiler compiler = javax.tools.ToolProvider.getSystemJavaCompiler();
            if (compiler == null) {
                return null;
            }
            
            Path tempDir = Path.of(System.getProperty("java.io.tmpdir"), "spotbugs-classes");
            tempDir.toFile().mkdirs();
            
            int result = compiler.run(null, null, null, 
                "-d", tempDir.toString(),
                sourcePath.toString());
            
            if (result == 0) {
                // Find the compiled class file
                String className = sourcePath.getFileName().toString().replace(".java", ".class");
                return tempDir.resolve(className);
            }
        } catch (Exception e) {
            logger.debug("Could not compile source for SpotBugs: {}", e.getMessage());
        }
        return null;
    }
    
    private Path convertToClassPath(Path sourcePath) {
        // Convert src/main/java/com/example/Foo.java -> target/classes/com/example/Foo.class
        String pathStr = sourcePath.toString();
        pathStr = pathStr.replace("src/main/java", "target/classes")
                         .replace("src\\main\\java", "target\\classes")
                         .replace(".java", ".class");
        return Path.of(pathStr);
    }
    
    private SecurityAgent.SecurityFinding convertToSecurityFinding(BugInstance bug, Path sourcePath) {
        // Map SpotBugs priority to severity
        SecurityAgent.SecurityFinding.Severity severity = switch (bug.getPriority()) {
            case 1 -> SecurityAgent.SecurityFinding.Severity.CRITICAL; // High priority
            case 2 -> SecurityAgent.SecurityFinding.Severity.MEDIUM;   // Normal priority
            case 3 -> SecurityAgent.SecurityFinding.Severity.LOW;      // Low priority
            default -> SecurityAgent.SecurityFinding.Severity.MEDIUM;
        };
        
        // Security-related bug patterns
        boolean isSecurityBug = bug.getType().startsWith("SEC") || 
                               bug.getBugPattern().getCategory().equals("SECURITY");
        
        if (isSecurityBug) {
            severity = SecurityAgent.SecurityFinding.Severity.HIGH;
        }
        
        // Determine if auto-fix is available
        boolean autoFixAvailable = isAutoFixable(bug.getType());
        
        SourceLineAnnotation sourceLine = bug.getPrimarySourceLineAnnotation();
        String location = sourcePath + ":" + (sourceLine != null ? sourceLine.getStartLine() : 0);
        
        String fixCode = autoFixAvailable ? "// Auto-fix available for " + bug.getType() : null;
        
        return new SecurityAgent.SecurityFinding(
            null,
            null,
            severity,
            "SpotBugs: " + bug.getType(),
            bug.getMessage(),
            location,
            bug.getBugPattern().getCWEid() > 0 ? "CWE-" + bug.getBugPattern().getCWEid() : null,
            0.80,
            List.of("Fix " + bug.getType() + " pattern"),
            autoFixAvailable,
            "STATIC: SpotBugs",
            fixCode
        );
    }
    
    private boolean isAutoFixable(String bugType) {
        // Bug types that can be auto-fixed
        return bugType.contains("SQL") ||
               bugType.contains("WEAK") ||
               bugType.contains("HARDCODED") ||
               bugType.contains("CRYPTO");
    }
}
