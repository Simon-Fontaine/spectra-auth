# Security Policy

Spectra Auth is committed to ensuring the security of your application and protecting sensitive user data. This document outlines our security practices and guidelines for reporting vulnerabilities.

## Reporting Vulnerabilities

If you discover a security vulnerability in Spectra Auth, please report it immediately. We take all security reports seriously and will work to address any issues as quickly as possible.

**How to Report:**

- **Email:** [github@simonfontaine.com](mailto:github@simonfontaine.com)
- **GitHub Issues:** [https://github.com/Simon-Fontaine/spectra-auth/issues](https://github.com/Simon-Fontaine/spectra-auth/issues)

When reporting a vulnerability, please include:

- A clear description of the vulnerability and its impact.
- Steps to reproduce the issue.
- Any relevant logs or error messages.
- Suggested remediation, if possible.

## Handling Secrets and Sensitive Data

- **Environment Variables:**  
  All sensitive configuration (e.g., `SESSION_TOKEN_SECRET`, `CSRF_SECRET`) must be stored in environment variables. Never hard-code secrets in your source code.

- **Secret Rotation:**  
  We recommend rotating all secrets regularly (e.g., every 90 days) to minimize the risk if a secret is compromised.

- **Production Settings:**  
  Replace all default secret values (such as `"change-me"`) with strong, randomly generated secrets before deploying to production.

## Cryptographic Best Practices

- **Session Tokens & CSRF Tokens:**  
  - Session tokens are generated using a cryptographically secure random number generator and signed using HMAC.
  - CSRF tokens are similarly generated and signed. Note that the CSRF cookie is now set to be accessible by client-side code (i.e., `httpOnly: false`) to facilitate client-side frameworks in retrieving the token.
  - Always ensure the token secrets are kept confidential and rotated regularly.

- **Password Hashing:**  
  Spectra Auth uses the scrypt algorithm with configurable parameters for password hashing. Adjust the cost factor, block size, and other parameters to balance security with performance based on your deployment environment.

## Rate Limiting

- **Brute-Force Protection:**  
  The package implements per-route rate limiting using Upstash Redis. Ensure that you provide valid Upstash credentials in production environments to protect against brute-force attacks.

- **Configuration:**  
  Adjust the rate limiting parameters (max requests and time windows) as needed to suit your application’s security requirements.

## Logging & Monitoring

- **Security Event Logging:**  
  All key security events (e.g., failed logins, token usage, rate limit violations) are logged using the built-in logger. Monitor these logs for unusual activity.

- **Audit Trails:**  
  Maintain logs and audit trails of authentication and security-related events to aid in forensic analysis in the event of a security incident.

## Response to Security Incidents

Upon receiving a report of a vulnerability, we will:

1. Acknowledge receipt of your report.
2. Investigate the issue and work on a fix.
3. Notify you (and, if necessary, the public) once the vulnerability has been resolved.

Your cooperation in responsibly reporting security issues helps us keep Spectra Auth secure for everyone.

Thank you for your vigilance and for helping us maintain the highest security standards.
