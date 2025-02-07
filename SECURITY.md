# Security Policy

## 1. Reporting Vulnerabilities

If you discover a security vulnerability, please contact @Simon-Fontaine at [github@simonfontaine.com](mailto:github@simonfontaine.com).

## 2. Handling Secrets

- **SESSION_TOKEN_SECRET**, **CSRF_SECRET**, and **PASSWORD_PEPPER** should be set in environment variables.
- Rotate these secrets periodically (e.g., every 90 days).

## 3. OWASP Best Practices

- **CSRF**: Ensure you always set and validate CSRF tokens on state-changing requests.
- **Rate Limiting**: Provide valid Upstash credentials in production to prevent brute-force attacks.
- **Password Storage**: By default, Argon2 is used for hashing. Configure Argon2 parameters to meet your performance & security needs.

## 4. Log & Monitor

- Use the built-in logger or supply your own. Monitor logs for suspicious behavior (multiple failed logins, repeated password reset requests, etc.).
- Consider hooking into a SIEM (Security Information and Event Management) solution for real-time alerts.

## 5. Patch Management

- Keep dependencies up to date. Run `npm audit` or similar tools regularly.
