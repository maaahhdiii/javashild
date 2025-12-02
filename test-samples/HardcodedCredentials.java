package com.example.vulnerable;

/**
 * VULNERABLE CODE - Hardcoded Credentials
 * DO NOT USE IN PRODUCTION!
 */
public class HardcodedCredentials {
    
    // CRITICAL: Hardcoded database password
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String DB_USER = "admin";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    
    // CRITICAL: Hardcoded API keys
    private String apiKey = "api_key_FAKE123456789ABCDEFGH";
    private String secretKey = "secret_FAKE987654321XYZ";
    
    // HIGH: AWS credentials in code
    public void connectToAWS() {
        String accessKey = "AKIA_FAKE_ACCESS_KEY_EXAMPLE";
        String secretAccessKey = "FakeSecretAccessKey123456789Example";
    }
    
    // HIGH: SSH private key in string
    private static final String SSH_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIIEpAIBAAKCAQEAw8r6N9pOjJ3N1y8I3k5fYz6wZ...\n" +
        "-----END RSA PRIVATE KEY-----";
    
    // CRITICAL: JWT secret
    private String jwtSecret = "myJWTSecretKey2024!SuperSecret";
    
    // HIGH: Email credentials
    public void sendEmail() {
        String smtpUser = "noreply@company.com";
        String smtpPass = "EmailPass123!";
    }
    
    // CRITICAL: Encryption key in code
    private byte[] encryptionKey = "1234567890123456".getBytes();
    
    // HIGH: OAuth client secret
    private String oauthClientSecret = "d84f6a8b-c3e2-4f1a-9b7d-8e3c2f1a9b7d";
}
