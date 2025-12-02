# Vulnerable Java Code Samples

⚠️ **WARNING: These files contain intentional security vulnerabilities for testing purposes only!**

## DO NOT USE IN PRODUCTION!

This directory contains Java code with various security vulnerabilities designed to test the JavaShield security analysis platform.

## Test Files

### 1. SQLInjection.java
- **Critical**: Direct SQL injection in login
- **Critical**: SQL injection in search queries
- **High**: Dynamic table name injection
- **Critical**: Order by clause injection
- **High**: Stored procedure injection

### 2. HardcodedCredentials.java
- **Critical**: Database passwords in code
- **Critical**: API keys hardcoded
- **High**: AWS credentials exposed
- **High**: SSH private keys in strings
- **Critical**: JWT secrets in code
- **High**: Email credentials
- **Critical**: Encryption keys hardcoded
- **High**: OAuth client secrets

### 3. InsecureDeserialization.java
- **Critical**: Deserializing untrusted data (RCE risk)
- **Critical**: Reading objects from network
- **High**: File deserialization without validation
- **Critical**: readUnshared without type checking
- **High**: XMLDecoder vulnerability

### 4. PathTraversal.java
- **Critical**: Directory traversal in file reading
- **Critical**: File download vulnerability
- **High**: Image serving path traversal
- **Critical**: File deletion vulnerability
- **High**: Log file access
- **Critical**: Zip slip vulnerability

### 5. XXEInjection.java
- **Critical**: XML External Entity injection
- **Critical**: SAX parser without protection
- **High**: XPath injection
- **Critical**: Unsafe XML unmarshalling
- **High**: XSLT transformation RCE

### 6. CommandInjection.java
- **Critical**: OS command injection
- **Critical**: Shell command with user input
- **High**: ProcessBuilder injection
- **Critical**: Database command injection
- **High**: Git command injection
- **Critical**: JavaScript eval injection
- **High**: LDAP injection

### 7. XSS.java
- **Critical**: Reflected XSS
- **High**: Stored XSS
- **Critical**: DOM-based XSS
- **High**: XSS in JSON responses
- **Critical**: XSS in error messages
- **High**: XSS in URL parameters

### 8. InsecureCrypto.java
- **Critical**: Using DES encryption (broken)
- **High**: ECB mode usage
- **Critical**: Weak random number generator
- **High**: MD5 password hashing
- **Critical**: No salt in hashes
- **High**: Small RSA key size (512-bit)
- **Critical**: Static IV usage

### 9. InsecureNetwork.java
- **Critical**: Trusting all SSL certificates
- **High**: Disabled hostname verification
- **Critical**: Using HTTP for sensitive data
- **High**: Weak TLS versions
- **Critical**: FTP credentials in cleartext
- **High**: Unencrypted socket communication

## How to Test

### Using the Web Interface:

1. **Navigate to**: http://localhost:8080
2. **Go to "File Upload" tab**
3. **Drag and drop** any of these .java files
4. **Click "Analyze Code"** button
5. **Review findings** with severity levels and recommendations

### Using Code Analysis Tab:

1. **Open any file** from this directory
2. **Copy the code**
3. **Go to "Code Analysis" tab**
4. **Paste into the editor**
5. **Click "Analyze Code"**

## Expected Results

Each file should trigger multiple security findings:
- ✅ **Critical findings**: 3-6 per file
- ✅ **High findings**: 2-4 per file
- ✅ **Confidence scores**: 75-95%
- ✅ **Recommendations**: Specific fix suggestions

## Severity Levels

- 🔴 **CRITICAL**: Immediate exploitation possible, RCE risk
- 🟠 **HIGH**: Major security risk, data breach possible
- 🟡 **MEDIUM**: Security weakness, should be fixed
- 🟢 **LOW**: Minor issue, best practice violation

## Testing Checklist

- [ ] Test SQL Injection detection
- [ ] Test Hardcoded Credentials detection
- [ ] Test Deserialization vulnerabilities
- [ ] Test Path Traversal detection
- [ ] Test XXE Injection detection
- [ ] Test Command Injection detection
- [ ] Test XSS detection
- [ ] Test Cryptographic weaknesses
- [ ] Test Network security issues

## Notes

- All code is intentionally vulnerable
- Never deploy these files to production
- Use only in isolated test environments
- Perfect for testing JavaShield's detection capabilities

---

**Created for JavaShield Testing** | Java 25 | Spring Boot 3.4
