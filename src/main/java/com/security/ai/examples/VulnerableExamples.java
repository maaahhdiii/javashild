package com.security.ai.examples;

import java.io.*;
import java.sql.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;

/**
 * INTENTIONALLY VULNERABLE CODE FOR TESTING
 * This class contains multiple security vulnerabilities for demonstration purposes.
 * DO NOT use this code in production!
 */
public class VulnerableExamples {
    
    // CWE-798: Hardcoded Credentials
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk-1234567890abcdef";
    private static final String SECRET_TOKEN = "my-secret-token-12345";
    
    /**
     * CWE-89: SQL Injection Vulnerability
     */
    public User authenticateUser(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost/mydb",
            "root",
            DB_PASSWORD  // Hardcoded password
        );
        
        // SQL Injection: Concatenating user input directly
        String query = "SELECT * FROM users WHERE username='" + username + 
                      "' AND password='" + password + "'";
        
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        
        if (rs.next()) {
            return new User(rs.getString("username"), rs.getString("email"));
        }
        
        return null;
    }
    
    /**
     * CWE-22: Path Traversal Vulnerability
     */
    public String readUserFile(String filename) throws IOException {
        // Path traversal: No validation of filename
        File file = new File("/var/www/uploads/" + filename);
        
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        
        reader.close();
        return content.toString();
    }
    
    /**
     * CWE-611: XML External Entity (XXE) Vulnerability
     */
    public void parseXMLInput(String xmlData) throws Exception {
        // XXE: XML parser not configured securely
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        
        // Vulnerable: External entities enabled by default
        org.w3c.dom.Document doc = builder.parse(new InputSource(new StringReader(xmlData)));
        
        System.out.println("Parsed XML: " + doc.getDocumentElement().getNodeName());
    }
    
    /**
     * CWE-502: Insecure Deserialization
     */
    public Object deserializeUserData(byte[] data) throws IOException, ClassNotFoundException {
        // Insecure deserialization: No validation of data
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        
        // Dangerous: Can execute arbitrary code
        Object obj = ois.readObject();
        
        ois.close();
        return obj;
    }
    
    /**
     * CWE-78: OS Command Injection
     */
    public String executeCommand(String userInput) throws IOException {
        // Command injection: User input directly in command
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("ls -la " + userInput);
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        
        return output.toString();
    }
    
    /**
     * CWE-319: Cleartext Transmission of Sensitive Information
     */
    public void sendCredentials(String username, String password) throws Exception {
        // Insecure: Using HTTP instead of HTTPS
        java.net.URL url = new java.net.URL("http://api.example.com/login");
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
        
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        
        String data = "username=" + username + "&password=" + password;
        
        try (OutputStream os = conn.getOutputStream()) {
            os.write(data.getBytes());
        }
        
        int responseCode = conn.getResponseCode();
        System.out.println("Response: " + responseCode);
    }
    
    /**
     * CWE-330: Use of Insufficiently Random Values
     */
    public String generateSessionToken() {
        // Weak: Using Math.random() for security token
        long token = (long) (Math.random() * Long.MAX_VALUE);
        return Long.toHexString(token);
    }
    
    /**
     * CWE-327: Use of a Broken or Risky Cryptographic Algorithm
     */
    public String hashPassword(String password) throws Exception {
        // Weak: Using MD5 for password hashing
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        
        return hexString.toString();
    }
    
    /**
     * CWE-79: Cross-Site Scripting (XSS)
     */
    public String renderUserComment(String comment) {
        // XSS: No HTML escaping of user input
        return "<div class='comment'>" + comment + "</div>";
    }
    
    /**
     * CWE-209: Information Exposure Through Error Message
     */
    public void processPayment(String cardNumber) {
        try {
            // Payment processing logic
            if (cardNumber.length() != 16) {
                throw new Exception("Invalid card number: " + cardNumber);
            }
            // Process payment...
        } catch (Exception e) {
            // Exposing sensitive information in error message
            System.err.println("Payment failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * CWE-501: Trust Boundary Violation
     */
    public void storeUserData(javax.servlet.http.HttpServletRequest request) {
        // Trust boundary violation: Storing untrusted data
        String userData = request.getParameter("userData");
        request.getSession().setAttribute("userData", userData);
    }
    
    /**
     * CWE-918: Server-Side Request Forgery (SSRF)
     */
    public String fetchURL(String url) throws IOException {
        // SSRF: No validation of URL
        java.net.URL targetURL = new java.net.URL(url);
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) targetURL.openConnection();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream())
        );
        
        StringBuilder content = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        
        return content.toString();
    }
    
    /**
     * CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
     */
    private int counter = 0;
    
    public void incrementCounter() {
        // Race condition: No synchronization
        counter++;
    }
    
    /**
     * CWE-476: NULL Pointer Dereference
     */
    public String getUserName(User user) {
        // Potential NPE: No null check
        return user.getUsername().toUpperCase();
    }
    
    /**
     * CWE-400: Uncontrolled Resource Consumption
     */
    public void processLargeFile(String filename) throws IOException {
        // Resource exhaustion: No size limit
        FileInputStream fis = new FileInputStream(filename);
        byte[] buffer = new byte[1024 * 1024 * 1024]; // 1GB buffer
        fis.read(buffer);
        fis.close();
    }
    
    // Helper classes
    static class User {
        private String username;
        private String email;
        
        public User(String username, String email) {
            this.username = username;
            this.email = email;
        }
        
        public String getUsername() {
            return username;
        }
        
        public String getEmail() {
            return email;
        }
    }
}
