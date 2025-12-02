# Vulnerable Code Examples

This directory contains **intentionally vulnerable code** for testing the security agent system.

⚠️ **WARNING**: These examples contain real security vulnerabilities. **NEVER** use this code in production!

## Purpose

These examples are used to:
1. Test the detection capabilities of the security agents
2. Demonstrate vulnerability patterns
3. Validate ML classification accuracy
4. Train automated response mechanisms

## Vulnerabilities Included

| CWE ID | Vulnerability | Severity | File |
|--------|---------------|----------|------|
| CWE-89 | SQL Injection | CRITICAL | VulnerableExamples.java:25 |
| CWE-798 | Hardcoded Credentials | HIGH | VulnerableExamples.java:14-16 |
| CWE-22 | Path Traversal | HIGH | VulnerableExamples.java:46 |
| CWE-611 | XML External Entity | HIGH | VulnerableExamples.java:63 |
| CWE-502 | Insecure Deserialization | HIGH | VulnerableExamples.java:77 |
| CWE-78 | Command Injection | CRITICAL | VulnerableExamples.java:90 |
| CWE-319 | Cleartext Transmission | HIGH | VulnerableExamples.java:108 |
| CWE-330 | Weak Random Values | MEDIUM | VulnerableExamples.java:130 |
| CWE-327 | Weak Crypto Algorithm | MEDIUM | VulnerableExamples.java:140 |
| CWE-79 | Cross-Site Scripting | MEDIUM | VulnerableExamples.java:156 |
| CWE-209 | Information Exposure | MEDIUM | VulnerableExamples.java:164 |
| CWE-501 | Trust Boundary Violation | MEDIUM | VulnerableExamples.java:180 |
| CWE-918 | Server-Side Request Forgery | HIGH | VulnerableExamples.java:189 |
| CWE-362 | Race Condition | LOW | VulnerableExamples.java:210 |
| CWE-476 | NULL Pointer Dereference | LOW | VulnerableExamples.java:219 |
| CWE-400 | Resource Exhaustion | MEDIUM | VulnerableExamples.java:227 |

## Testing

Run the security scan on these examples:

```bash
java --enable-preview -jar vulnerability-detection-agent.jar \
  --scan --path src/main/java/com/security/ai/examples/
```

Expected Results:
- 16 vulnerabilities detected
- 2 CRITICAL severity
- 7 HIGH severity
- 5 MEDIUM severity
- 2 LOW severity

## Safe Usage

These files are safe to have in your repository because:
1. They are clearly marked as vulnerable examples
2. They are not compiled into the final JAR
3. They are excluded from production builds
4. They serve an educational purpose

## References

- [CWE Database](https://cwe.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
