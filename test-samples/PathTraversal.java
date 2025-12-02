package com.example.vulnerable;

import java.io.*;
import java.nio.file.*;

/**
 * VULNERABLE CODE - Path Traversal
 * DO NOT USE IN PRODUCTION!
 */
public class PathTraversal {
    
    // CRITICAL: Direct file access without validation
    public String readFile(String filename) throws IOException {
        File file = new File("/var/www/uploads/" + filename);
        // Attacker can use: ../../../../etc/passwd
        return new String(Files.readAllBytes(file.toPath()));
    }
    
    // CRITICAL: File download vulnerability
    public void downloadFile(String userPath) throws IOException {
        String basePath = "/app/files/";
        FileInputStream fis = new FileInputStream(basePath + userPath);
        // Can access: ../../../etc/shadow
    }
    
    // HIGH: Image serving vulnerability
    public byte[] getImage(String imageName) throws IOException {
        String imagePath = "./images/" + imageName;
        return Files.readAllBytes(Paths.get(imagePath));
        // Vulnerable to: ../config/database.properties
    }
    
    // CRITICAL: File deletion vulnerability
    public void deleteUserFile(String filename) {
        File file = new File("/tmp/user_files/" + filename);
        file.delete();
        // Can delete: ../../../important/system/file
    }
    
    // HIGH: Log file access
    public String viewLogs(String logFile) throws IOException {
        Path logPath = Paths.get("/var/logs/" + logFile);
        return new String(Files.readAllBytes(logPath));
        // Access: ../../etc/passwd
    }
    
    // CRITICAL: Zip extraction vulnerability
    public void extractZip(String zipPath) throws IOException {
        java.util.zip.ZipInputStream zis = new java.util.zip.ZipInputStream(
            new FileInputStream(zipPath));
        java.util.zip.ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File file = new File("/extract/" + entry.getName());
            // Zip slip vulnerability - can write anywhere
            FileOutputStream fos = new FileOutputStream(file);
        }
    }
}
