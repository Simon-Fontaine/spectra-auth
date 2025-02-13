# Security Policy for Aegis Auth

Aegis Auth is designed with security as a top priority. This document outlines the security practices and measures implemented in the library, as well as guidelines for reporting vulnerabilities.

## Reporting Vulnerabilities

If you discover a security vulnerability in Aegis Auth, **please report it immediately**. We take all security reports seriously and will work to address any issues as quickly as possible.

**How to Report:**

- **Email:** [github@simonfontaine.com](mailto:github@simonfontaine.com) (Preferred for sensitive information.)
- **GitHub Issues:** [https://github.com/Simon-Fontaine/aegis-auth/issues](https://github.com/Simon-Fontaine/aegis-auth/issues) (Use for less critical vulnerabilities or if you prefer public disclosure after a fix.)

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

- **Environment Variables:** All sensitive configuration options, such as `SESSION_TOKEN_SECRET`, `CSRF_SECRET`, `KV_REST_API_URL`, and `KV_REST_API_TOKEN`, *must* be stored in environment variables. **Never** hardcode secrets in source code.
- **Secret Rotation:** Regularly rotate secrets (e.g., every 90 days or more frequently for highly sensitive applications) to limit the impact of a leaked secret.
- **Strong Secrets:** Use strong, randomly generated secrets. For example:

  ```bash
  openssl rand -base64 32
  ```

### 2. Cryptography

- **Password Hashing:** Uses the **scrypt** algorithm, which is memory-hard and helps resist brute force. All parameters are configurable.
- **Session Tokens:** Generated via a cryptographically secure RNG (`uncrypto`). **Only** an HMAC-SHA256 hash of the token is stored in the DB, preventing stolen DB contents from impersonating users.
- **CSRF Tokens:** Also generated securely and protected with HMAC-SHA256. Uses a separate secret from the session token.
- **HMAC:** Ensures the integrity and authenticity of tokens.
- **Timing Safe Equal:** Compares hashes using `timingSafeEqual` to mitigate timing attacks.

### 3. Session Management

- **`httpOnly` Cookies:** Session cookies are sent with `httpOnly` to reduce XSS risk.
- **`Secure` Cookies:** Session/CSRF cookies are `Secure` in production to ensure HTTPS-only.
- **`SameSite` Cookies:** Default is `Lax`, mitigating CSRF attacks while allowing top-level navigation flows.
- **Session Expiration:** Configurable max age (`maxAgeSeconds`).
- **Session Rolling:** Automatic rotation after `rollingIntervalSeconds` to reduce the window for stolen tokens.
- **Session Revocation:** Sessions can be revoked on logout or forced upon events like password reset.
- **Concurrent Session Limits:** Set a maximum for how many sessions a user can have at once.

### 4. CSRF Protection

- **`httpOnly` CSRF Cookies:** If you choose to set them `httpOnly`, be aware you need a separate endpoint to fetch the token via server code. By default, `cookieHttpOnly` is `false` so the client can read the token.
- **API Endpoint for CSRF Token:** Required if you want your client to fetch the CSRF token from the server.
- **Verification:** The server checks each state-changing request’s `X-CSRF-Token` header against what’s stored in the session.

### 5. Rate Limiting

- **Upstash Redis:** Used for IP-based rate limiting.
- **Per-Route Limits:** Configurable for login, registration, email verification, password resets, etc.
- **IP-Based:** By default, keyed on the client’s IP address.

### 6. Account Security

- **Account Lockout:** After a configurable number of failed logins, the account is locked for a set duration.
- **Email Verification:** Optionally enforced on registration (`requireEmailVerification`).

### 7. Logging

- **Security Events:** Logs critical security-related events (e.g., failed logins, session creation, revocation).
- **Audit Trails:** Monitor these for suspicious activity. Store logs securely for auditing.

### 8. Input Validation

- **Zod:** Used to validate all user inputs. Helps prevent injection attacks by ensuring data matches expected formats.
- **Password Complexity:** Enforced by default with uppercase, lowercase, digits, and special chars.

## Additional Best Practices

- **Keep Secrets Secret:** Never commit secrets. Use environment variables.
- **HTTPS:** Always use HTTPS in production.
- **Monitor Logs:** Regularly review logs for anomalies.
- **Keep Dependencies Updated:** Stay current to benefit from security patches.
- **Test Thoroughly:** Unit, integration, and e2e tests are recommended.  
- **Restrict Role-Based Actions:** If you have admin-only actions (like `banUser` or `unbanUser`), ensure your application checks user roles (not handled automatically by Aegis Auth).

By following these security measures and guidelines, you can significantly enhance the security of your application and protect your users’ data.
