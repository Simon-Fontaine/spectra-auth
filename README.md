# Aegis Auth

Aegis Auth is a robust, secure, and flexible authentication solution for Next.js and Node.js applications. It provides credentials-based authentication with built-in session management, rate limiting, account lockouts, password resets, email verification, and CSRF protection.  Aegis Auth is designed to be easy to integrate and customize, while prioritizing security best practices.

## Features

- **User Registration & Login:** Secure endpoints for creating accounts and logging in.
- **Session Management:** Automatically generates and verifies cryptographically secure session tokens (stored as hashes in the database).  Enforces a configurable maximum number of active sessions per user and supports session rolling.
- **Password Security:** Uses scrypt with configurable parameters for hashing passwords with a unique salt.
- **Email Verification & Password Reset:** Token-based flows for verifying email addresses and resetting passwords.
- **Rate Limiting:** Protects endpoints (login, registration, etc.) with per-route rate limiting using Upstash Redis.
- **CSRF Protection:** Generates secure CSRF tokens stored in `httpOnly` cookies.  Provides a mechanism for client-side frameworks to access the token via a dedicated API endpoint.
- **Account Security:** Implements account lockouts after repeated failed login attempts and comprehensive logging of security events.
- **Flexible Configuration:** Customize every aspect—from cryptographic parameters to cookie settings—using a centralized configuration.

## Installation

```bash
npm install aegis-auth
# or
yarn add aegis-auth
```

## Requirements

- Node.js v14+
- [Prisma](https://www.prisma.io/) (for database connectivity)
- Upstash Redis credentials (for production rate limiting)

## Setup

### 1. Environment Variables

Create a `.env` file (or configure your environment variables directly) with the following:

```env
DATABASE_URL="your_postgresql_connection_string"
SESSION_TOKEN_SECRET="a_very_strong_random_secret"  # Generate with: openssl rand -base64 32
CSRF_SECRET="another_very_strong_random_secret"      # Generate with: openssl rand -base64 32
KV_REST_API_URL="your_upstash_redis_rest_api_url"
KV_REST_API_TOKEN="your_upstash_redis_rest_api_token"

# Optional: For email sending with Resend
RESEND_API_KEY="your_resend_api_key"
EMAIL_FROM="[email address removed]"
```

**Important:**

- `SESSION_TOKEN_SECRET` and `CSRF_SECRET` *must* be strong, randomly generated secrets. **Do not use the example values in production.**
- The Upstash Redis variables are required for rate limiting to function correctly in production.

### 2. Prisma Schema

Copy the following schema into your `prisma/schema.prisma` file:

```prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

enum VerificationType {
  EMAIL_VERIFICATION
  PASSWORD_RESET
  ACCOUNT_DELETION
  EMAIL_CHANGE
}

model User {
  id                String    @id @default(uuid())
  username          String    @unique
  email             String    @unique
  password          String
  pendingEmail      String?   @unique
  isEmailVerified   Boolean   @default(false)
  isBanned          Boolean   @default(false)
  failedLoginAttempts Int       @default(0)
  lockedUntil       DateTime?
  avatarUrl         String?
  displayName       String?
  roles             String[]
  createdAt         DateTime  @default(now())
  updatedAt         DateTime  @updatedAt

  sessions      Session[]
  verifications Verification[]

  @@index([email, isBanned])
  @@index([lockedUntil])
  @@map("users")
}

model Session {
  id            String   @id @default(uuid())
  userId        String
  tokenHash     String   @unique
  csrfTokenHash String   @unique
  isRevoked     Boolean  @default(false)
  expiresAt     DateTime
  createdAt     DateTime @default(now())
  updatedAt     DateTime @updatedAt
  ipAddress     String?
  location      String?
  country       String?
  device        String?
  browser       String?
  os            String?
  userAgent     String?

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([expiresAt])
  @@index([isRevoked])
  @@map("sessions")
}

model Verification {
  id        String           @id @default(uuid())
  userId    String
  token     String           @unique
  type      VerificationType
  metadata  Json?
  expiresAt DateTime
  usedAt    DateTime?
  createdAt DateTime         @default(now())
  updatedAt DateTime         @updatedAt

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@map("verifications")
}
```

Then, run your Prisma migrations:

```bash
npx prisma migrate dev
```

### 3. Instantiation

Create an instance of `AegisAuth` in your application:

```typescript
import { PrismaClient } from "@prisma/client";
import { AegisAuth } from "aegis-auth";

const prisma = new PrismaClient();
const auth = new AegisAuth(prisma, {
  // Optional: Override default configuration settings here.
  // See src/config/schema.ts for all options.
  // Example:
  // session: {
  //   maxAgeSeconds: 60 * 60 * 24 * 14, // 14 days
  // },
});

export { auth }; // Export the instance for use throughout your app.
```

### 4. CSRF Token Endpoint (for Client-Side Frameworks)

Create an API endpoint (e.g., `/api/csrf-token`) to provide the CSRF token to your client-side application.  This is necessary because the CSRF cookie is `httpOnly`.

**Example (Next.js API Route):**

```typescript
// pages/api/csrf-token.ts
import { NextApiRequest, NextApiResponse } from 'next';
import { auth } from '../../path/to/your/auth/instance'; // Import your AegisAuth instance
import { getCsrfToken } from 'aegis-auth/src/cookies';

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  if (req.method !== 'GET') {
    return res.status(405).end(); // Method Not Allowed
  }

  const sessionToken = req.cookies['aegis.sessionToken']; // Use correct cookie name
  if (!sessionToken) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const sessionValidation = await auth.validateAndRotateSession({
    options: {
        input: {
            sessionToken: sessionToken,
        },
    },
  });

  if (!sessionValidation.success) {
    return res.status(401).json({ message: sessionValidation.message });
  }


  const csrfToken = getCsrfToken({ cookieHeader: req.headers.cookie!, config: auth.config });

  if(!csrfToken) {
      return res.status(401).json({message: 'CSRF token not found.'})
  }

  return res.status(200).json({ csrfToken });
}
```

In your client-side code, fetch the CSRF token from this endpoint and include it in the `X-CSRF-Token` header (or a custom header of your choice) for all state-changing requests (POST, PUT, DELETE, PATCH).

## Usage Examples

**Important:**  All examples assume you have instantiated `AegisAuth` as shown above and exported it as `auth`.  The examples also assume you're handling the HTTP request and response (e.g., within a Next.js API route or an Express.js handler). You are responsible for setting cookies using a library such as `cookie` as shown in the API docs.

```typescript
// Example using the 'cookie' package
import { serialize } from 'cookie';
// ... inside your request handler ...
res.setHeader('Set-Cookie', [
    serialize('aegis.sessionToken', sessionToken, {/* ... cookie options ... */}),
    serialize('aegis.csrfToken', csrfToken, {/* ... cookie options ... */}),
]);

```

### User Registration

```typescript
// pages/api/register.ts
import { NextApiRequest, NextApiResponse } from 'next';
import { auth } from '../../path/to/your/auth/instance';
import { serialize } from 'cookie';


export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  if (req.method !== 'POST') {
    return res.status(405).end(); // Method Not Allowed
  }

    if (req.method !== 'POST') {
        return res.status(405).end();
    }

    const csrfToken = req.headers['x-csrf-token'] as string;

    if (!csrfToken) {
        return res.status(403).json({ message: 'CSRF token required' });
    }

  const { username, email, password } = req.body;
  const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  const registrationResult = await auth.registerUser({
    options: {
      input: { username, email, password },
      ipAddress: ipAddress as string, // Ensure ipAddress is a string
      headers: req.headers as Record<string, string>
    },
  });

  if (registrationResult.success) {

      // Email verification is handled by Aegis Auth.  You don't need to
      // manually send a response for it here, unless you want to provide
      // custom messaging.
      return res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.' });

  } else {
    return res.status(registrationResult.status).json({ message: registrationResult.message });
  }
}
```

### User Login

```typescript
// pages/api/login.ts
import { NextApiRequest, NextApiResponse } from 'next';
import { auth } from '../../path/to/your/auth/instance';
import { createSessionCookie, createCsrfCookie } from 'aegis-auth/src/cookies';

export default async function handler(
    req: NextApiRequest,
    res: NextApiResponse
) {
    if (req.method !== 'POST') {
        return res.status(405).end();
    }

    const csrfToken = req.headers['x-csrf-token'] as string;

    if (!csrfToken) {
        return res.status(403).json({ message: 'CSRF token required' });
    }

    const { usernameOrEmail, password } = req.body;
    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const loginResult = await auth.loginUser({
        options: {
            input: { usernameOrEmail, password },
            ipAddress: ipAddress as string,
            userAgent,
            headers: req.headers as Record<string, string>
        },
    });

    if (loginResult.success) {
        const { session, user } = loginResult.data!;
        const sessionCookie = createSessionCookie({ sessionToken: session.sessionToken, config: auth.config });
        const csrfCookie = createCsrfCookie({ csrfToken: session.csrfToken, config: auth.config });

        res.setHeader('Set-Cookie', [sessionCookie, csrfCookie]);
        return res.status(200).json({ message: 'Login successful', user });
    } else {
        return res.status(loginResult.status).json({ message: loginResult.message });
    }
}

```

### User Logout

```typescript
// pages/api/logout.ts
import { NextApiRequest, NextApiResponse } from 'next';
import { auth } from '../../path/to/your/auth/instance';
import { clearSessionCookie, clearCsrfCookie } from 'aegis-auth/src/cookies';

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  if (req.method !== 'POST') {
    return res.status(405).end();
  }

    const csrfToken = req.headers['x-csrf-token'] as string;

    if (!csrfToken) {
        return res.status(403).json({ message: 'CSRF token required' });
    }

  const sessionToken = req.cookies['aegis.sessionToken']; // Replace with your actual cookie name

  if (!sessionToken) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

    const session = await auth.validateAndRotateSession({options: {input: {sessionToken}}});

    if (!session.success || !session.data?.session) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const isValidCsrf = await auth.config.csrf.tokenSecret ? verifyCsrfToken({
        token: csrfToken,
        hash: session.data?.session.csrfTokenHash, // Get the hash from the newly created session
        config: auth.config,
    }) : false;

    if (!isValidCsrf) {
        return res.status(403).json({ message: "Invalid CSRF token." });
    }

  const logoutResult = await auth.logoutUser(sessionToken);

  if (logoutResult.success) {
    res.setHeader('Set-Cookie', [
      clearSessionCookie({ config: auth.config }),
      clearCsrfCookie({ config: auth.config }),
    ]);
    return res.status(200).json({ message: 'Logout successful' });
  } else {
    return res.status(logoutResult.status).json({ message: logoutResult.message });
  }
}
```

### Password Reset & Email Verification

See the [API Documentation](./docs/API.md) for detailed examples of these flows. They follow a similar pattern: initiate the process, then complete it using a token.

## Configuration

The package uses sensible defaults which you can override when instantiating the `AegisAuth` class.  Key configuration areas include:

- **Session Settings:** Cookie name, token length, max sessions per user, rolling interval, etc.
- **CSRF Settings:** Token length, cookie name, and `httpOnly` flag (should be `true`).
- **Rate Limiting:** Per-route limits for login, registration, email verification, etc.
- **Password Hashing:** Scrypt parameters (cost factor, block size, parallelization, key length).
- **Logging:** Provide your own logger if needed; by default, a `ConsoleLogger` is used.
- **Email:** Configure the Resend API key and email templates.

For complete configuration options and their defaults, check out the [configuration schema](./src/config/schema.ts).

## Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/Simon-Fontaine/aegis-auth).

## License

This project is licensed under the MIT License.
