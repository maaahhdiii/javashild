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
            // SpotBugs requires compiled .class files
            // First, try to compile the source file on-the-fly
            Path classPath = compileSource(sourcePath);
            
            if (classPath == null || !classPath.toFile().exists()) {
                // Try standard Maven structure
                classPath = convertToClassPath(sourcePath);
                if (!classPath.toFile().exists()) {
                    logger.debug("Class file not available for {}, skipping SpotBugs", sourcePath.getFileName());
                    return findings;
                }
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
            logger.debug("SpotBugs analysis skipped for {}: {}", sourcePath.getFileName(), e.getMessage());
        }
        
        return findings;
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
