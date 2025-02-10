# Security Policy for Aegis Auth

Aegis Auth is designed with security as a top priority. This document outlines the security practices and measures implemented in the library, as well as guidelines for reporting vulnerabilities.

## Reporting Vulnerabilities

If you discover a security vulnerability in Aegis Auth, **please report it immediately**.  We take all security reports seriously and will work to address any issues as quickly as possible.

**How to Report:**

- **Email:**  [github@simonfontaine.com](mailto:github@simonfontaine.com)  (This is the preferred method for sensitive information.)
- **GitHub Issues:** [https://github.com/Simon-Fontaine/aegis-auth/issues](https://github.com/Simon-Fontaine/aegis-auth/issues) (Use this for less critical vulnerabilities or if you prefer public disclosure after a fix.)

**When reporting, please include:**

- A clear and concise description of the vulnerability.
- The potential impact of the vulnerability.
- Detailed steps to reproduce the issue (including any code snippets, if applicable).
- The version(s) of Aegis Auth affected.
- Any suggested remediation (if you have one).

We will acknowledge receipt of your report and keep you informed of our progress in addressing the vulnerability. We request that you do not publicly disclose the vulnerability until we have had a reasonable opportunity to investigate and release a fix.

## Security Practices

Aegis Auth incorporates the following security practices:

### 1. Secrets Management

- **Environment Variables:** All sensitive configuration options, such as `SESSION_TOKEN_SECRET`, `CSRF_SECRET`, `KV_REST_API_URL`, and `KV_REST_API_TOKEN`, *must* be stored in environment variables.  **Never hardcode secrets directly into your source code.**
- **Secret Rotation:** We strongly recommend regularly rotating your secrets (e.g., every 90 days, or more frequently for highly sensitive applications). This minimizes the impact if a secret is ever compromised.
- **Strong Secrets:** Use strong, randomly generated secrets.  You can generate suitable secrets using tools like `openssl`:

    ```bash
    openssl rand -base64 32
    ```

### 2. Cryptography

- **Password Hashing:** Aegis Auth uses the **scrypt** algorithm for password hashing, a memory-hard and computationally intensive algorithm designed to resist brute-force and rainbow table attacks.  Configurable parameters (cost factor, block size, parallelization) allow you to tune the security/performance trade-off.
- **Session Tokens:** Session tokens are generated using a cryptographically secure random number generator (`uncrypto`).  The *entire* session token is treated as a secret.  Only the *hash* of the session token (using HMAC-SHA256) is stored in the database. This prevents attackers from using stolen database contents to impersonate users.
- **CSRF Tokens:** CSRF tokens are also generated using a cryptographically secure random number generator and protected with HMAC-SHA256, using a separate secret from the session token secret.
- **HMAC:**  HMAC (Hash-based Message Authentication Code) with SHA-256 is used to sign both session tokens and CSRF tokens. This ensures the integrity and authenticity of the tokens.
- **Timing Safe Equal:** Compares hash using timingSafeEqual to prevent timing attacks.

### 3. Session Management

- **`httpOnly` Cookies:** Session cookies are set with the `httpOnly` flag, preventing client-side JavaScript from accessing them.  This is a crucial defense against Cross-Site Scripting (XSS) attacks.
- **`Secure` Cookies:** Session and CSRF cookies are set with the `Secure` flag (in production) to ensure they are only transmitted over HTTPS.
- **`SameSite` Cookies:**  The `SameSite` attribute is used (defaults to `Lax`) to help mitigate CSRF attacks.
- **Session Expiration:** Sessions have a configurable maximum age (`maxAgeSeconds`).
- **Session Rolling:** Aegis Auth supports session rolling, where a new session token is generated and the old one is revoked after a configurable interval (`rollingIntervalSeconds`).  This limits the window of opportunity for attackers who might have obtained a session token.
- **Session Revocation:**  Sessions can be explicitly revoked (e.g., on logout).  All sessions for a user are automatically revoked during a password reset.
- **Concurrent Session Limits:**  You can configure the maximum number of concurrent active sessions per user (`maxSessionsPerUser`).

### 4. CSRF Protection

- **`httpOnly` CSRF Cookies:** CSRF cookies are set with the `httpOnly` flag to prevent access from JavaScript.
- **API Endpoint for CSRF Token:** Aegis Auth requires you to create an API endpoint (e.g., `/api/csrf-token`) that is protected by session authentication. Client-side applications *must* fetch the CSRF token from this endpoint and include it in the `X-CSRF-Token` header (or a custom header of your choice) with all state-changing requests (POST, PUT, DELETE, PATCH).
- **Verification:** The server verifies the CSRF token on every state-changing request by comparing it to the hash stored in the user's session.

### 5. Rate Limiting

- **Upstash Redis:** Aegis Auth uses Upstash Redis for rate limiting.  This is a highly scalable and performant solution.
- **Per-Route Limits:** Rate limiting is applied on a per-route basis, with configurable limits for:
  - Login attempts
  - Registration attempts
  - Email verification requests
  - Password reset initiation requests
  - Password reset completion requests
- **IP-Based:** Rate limiting is based on the client's IP address.

### 6. Account Security

- **Account Lockout:** After a configurable number of failed login attempts (`maxFailedLogins`), accounts are temporarily locked (`lockoutDurationSeconds`).
- **Email Verification:** Aegis Auth supports optional email verification upon registration (`requireEmailVerification`).

### 7. Logging

- **Security Events:** Key security events (e.g., failed logins, successful logins, password resets, session creation, session revocation, rate limit violations, invalid tokens) are logged using a configurable logger.  By default, a `ConsoleLogger` is used, but you can provide your own logger.
- **Audit Trails:**  You should monitor these logs for suspicious activity and maintain them for auditing purposes.

### 8. Input Validation

- **Zod:**  Aegis Auth uses the Zod library for input validation.  This helps prevent common vulnerabilities like SQL injection and Cross-Site Scripting (XSS) by ensuring that user-provided data conforms to expected formats.
- **Password Complexity:** The password is validated to prevent the user to use a weak password.

## Best Practices

- **Keep Secrets Secret:** Never commit secrets to your code repository. Use environment variables.
- **HTTPS:** Always use HTTPS in production.
- **Monitor Logs:** Regularly review your application logs for any signs of suspicious activity.
- **Keep Dependencies Updated:** Regularly update Aegis Auth and all other dependencies to benefit from the latest security patches.
- **Test Thoroughly:**  Implement comprehensive unit and integration tests to ensure the security features of Aegis Auth are working as expected.
- **Use additional security layers:** Even if Aegis Auth is secured, you should add extra security layers, like a WAF, to prevent attacks.

By following these security practices and guidelines, you can significantly enhance the security of your application and protect your users' data.
