# Spectra Auth

Spectra Auth is a robust authentication solution for Next.js and Node.js applications. It offers secure, credentials-based authentication with built-in session management, rate limiting, account lockouts, password resets, email verification, and CSRF protection.

## Features

- **User Registration & Login:** Secure endpoints for creating accounts and logging in.
- **Session Management:** Automatically generates and verifies cryptographically signed session tokens. Enforces a configurable maximum number of active sessions per user and supports session rolling.
- **Password Security:** Uses scrypt with configurable parameters for hashing passwords with a unique salt.
- **Email Verification & Password Reset:** Token-based flows for verifying emails and resetting passwords.
- **Rate Limiting:** Protects endpoints (login, registration, etc.) with per-route rate limiting via Upstash Redis.
- **CSRF Protection:** Generates secure CSRF tokens stored in cookies (default is now client‑readable with `httpOnly: false`).
- **Account Security:** Implements account lockouts after repeated failed logins and comprehensive logging of security events.
- **Flexible Configuration:** Customize every aspect—from cryptographic parameters to cookie settings—using a centralized configuration.

## Installation

Install via npm or yarn:

```bash
npm install spectra-auth
# or
yarn add spectra-auth
```

## Requirements

- Node.js v14+
- [Prisma](https://www.prisma.io/) (for database connectivity)
- Upstash Redis credentials for production rate limiting

## Setup

### Environment Variables

Ensure you set the following environment variables in production:

- `DATABASE_URL` – Your PostgreSQL connection string.
- `SESSION_TOKEN_SECRET` – A strong secret for signing session tokens.
- `CSRF_SECRET` – A strong secret for signing CSRF tokens.
- `KV_REST_API_URL` and `KV_REST_API_TOKEN` – Credentials for Upstash Redis (used for rate limiting).

### Prisma

Make sure your Prisma schema is configured (see [prisma/schema.prisma](./prisma/schema.prisma)) and run the migrations:

```bash
npx prisma migrate dev
```

### Instantiating Spectra Auth

Create an instance of `SpectraAuth` in your application by passing in your Prisma client and (optionally) overriding default settings:

```typescript
import { PrismaClient } from "@prisma/client";
import { SpectraAuth } from "spectra-auth";

const prisma = new PrismaClient();
const auth = new SpectraAuth(prisma, {
  // Optional: Override default configuration settings here.
});
```

## Usage Examples

### User Registration

```typescript
const registrationResult = await auth.registerUser({
  options: {
    input: {
      username: "newuser",
      email: "user@example.com",
      password: "StrongP@ssw0rd!"
    },
    ipAddress: "127.0.0.1",
  },
});

if (registrationResult.success) {
  console.log("User registered successfully", registrationResult.data?.user);
} else {
  console.error("Registration failed:", registrationResult.message);
}
```

### User Login

```typescript
const loginResult = await auth.loginUser({
  options: {
    input: {
      usernameOrEmail: "newuser",
      password: "StrongP@ssw0rd!"
    },
    ipAddress: "127.0.0.1",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
  },
});

if (loginResult.success) {
  console.log("Login successful", loginResult.data?.user);
  // Use helper functions from src/cookies/ to create and set the session and CSRF cookies.
} else {
  console.error("Login error:", loginResult.message);
}
```

### Logging Out

```typescript
const logoutResult = await auth.logoutUser("sessionTokenHere");

if (logoutResult.success) {
  console.log("User logged out successfully");
} else {
  console.error("Logout error:", logoutResult.message);
}
```

### Password Reset & Email Verification

Spectra Auth provides dedicated methods for initiating and completing password resets as well as verifying email addresses. For example:

- `auth.initiatePasswordReset({...})`
- `auth.completePasswordReset({...})`
- `auth.verifyEmail({...})`

Refer to the [API documentation](./docs/API.md) for more details.

## Configuration

The package uses sensible defaults which you can override when instantiating the `SpectraAuth` class. Key configuration areas include:

- **Session Settings:** Cookie name, token length, max sessions per user, rolling interval, etc.
- **CSRF Settings:** Token length, cookie name, and the ability to make the cookie client‑readable.
- **Rate Limiting:** Per-route limits for login, registration, email verification, etc.
- **Password Hashing:** Scrypt parameters (cost factor, block size, parallelization, key length).
- **Logging:** Provide your own logger if needed; by default, the built‑in `ConsoleLogger` is used.

For complete configuration options, check out the [configuration schema](./src/config/schema.ts).

## Contributing

Contributions, bug reports, and feature requests are welcome. Please open an issue or submit a pull request on [GitHub](https://github.com/Simon-Fontaine/spectra-auth).

## License

This project is licensed under the MIT License.
