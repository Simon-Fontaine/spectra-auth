# Spectra Auth

A **credentials-based** authentication solution for Next.js (and other Node.js projects) featuring:

- **Database-backed sessions** (stored in [Prisma](https://www.prisma.io/))
- **IP rate-limiting** (powered by [Upstash Redis](https://upstash.com/))
- **Automatic account lockouts** after too many failed attempts
- **CSRF protection** to mitigate Cross-Site Request Forgery attacks
- **Email verification** and **password reset** flows
- Designed to integrate easily with **your own Prisma schema**, with minimal required fields

## Table of Contents

1. [Installation](#1. installation)  
2. [Prerequisites](#2. prerequisites)  
3. [Prisma Schema Setup](#3. prisma-schema-setup)  
4. [Environment Variables](#4. environment-variables)  
5. [Usage Example](#5. usage-example)  
6. [Available Methods](#6. available-methods)  
7. [Security Considerations](#7. security-considerations)
8. [Testing](#8. testing)  
9. [License](#9. license)

## 1. Installation

```bash
npm install spectra-auth

# or:
yarn add spectra-auth
pnpm add spectra-auth
```

## 2. Prerequisites

- **Prisma**: You need Prisma configured in your project to store `User`, `Session`, and `Verification` data.  
- **Upstash Redis**: Required for IP-based rate-limiting. If you don’t plan to use rate-limiting, you can mock or disable it in tests, but in production, you should set it up.

## 3. Prisma Schema Setup

In your `schema.prisma`, ensure you have the following (or equivalent) models. Spectra Auth expects at least these fields, though you can add more. If you rename fields, you may need to adapt some logic:

```prisma
enum VerificationType {
  EMAIL_VERIFICATION
  PASSWORD_RESET
  ACCOUNT_DELETION
  EMAIL_CHANGE
}

model User {
  id                  String    @id @default(uuid())
  username            String    @unique
  email               String    @unique
  password            String
  isEmailVerified     Boolean   @default(false)
  isBanned            Boolean   @default(false)
  failedLoginAttempts Int       @default(0)
  lockedUntil         DateTime?
  // Additional fields optional
  displayName         String?
  roles               String[]
  createdAt           DateTime  @default(now())
  updatedAt           DateTime  @updatedAt

  sessions      Session[]
  verifications Verification[]

  @@map("users")
}

model Session {
  id          String   @id @default(uuid())
  userId      String
  tokenPrefix String?
  tokenHash   String?
  isRevoked   Boolean  @default(false)
  expiresAt   DateTime
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  // Optional device info
  ipAddress   String?
  location    String?
  country     String?
  device      String?
  browser     String?
  userAgent   String?

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([tokenPrefix])
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

Once updated, run:

```bash
npx prisma generate # Important: regenerate Prisma client after schema changes

npx prisma db push
# or:
npx prisma migrate dev
```

## 4. Environment Variables

Spectra Auth uses Upstash for IP-based rate-limiting. You must set these environment variables so the library won’t complain at load time:

```bash
# .env
KV_REST_API_URL="<YOUR_KV_REST_API_URL>"
KV_REST_API_TOKEN="<YOUR_KV_REST_API_TOKEN>"

# Optional:
NODE_ENV="production"
```

- **`KV_REST_API_URL`** and **`KV_REST_API_TOKEN`** are **required** if you’re actually using rate-limiting in production.  

**Configuration:**

You can customize the behavior of Spectra Auth by passing a configuration object to `initSpectraAuth()`. This allows you to adjust settings like session expiration, account lockout thresholds, rate limiting parameters, and more. See the `src/config/defaults.ts` file for the default configuration and available options.

**Important Security Notes:**
It is **highly recommended** to configure rate limiting and **essential** to utilize CSRF protection in production environments. Ensure you set strong, unique secrets for CSRF and rotate them periodically.

## 5. Usage Example

Below is a minimal example using **Express**-style pseudocode. The same logic applies in Next.js or any Node environment:

```ts
// src/server.ts
import express from "express";
import { PrismaClient, User } from "@prisma/client";
import { initSpectraAuth, createSessionCookie, clearSessionCookie, getSessionTokenFromHeader } from "spectra-auth";

const app = express();
app.use(express.json());

const prisma = new PrismaClient();
const auth = initSpectraAuth(prisma);

// Simple middleware to check CSRF token (example)
async function csrfMiddleware(req, res, next) {
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
    const sessionToken = getSessionTokenFromHeader(req.headers.cookie ?? null);
    const csrfCookie = auth.getCSRFTokenFromCookies(req.headers.cookie);
    const csrfHeader = req.headers['x-csrf-token'] || req.body._csrf; // Or get from body

    if (!sessionToken || !csrfCookie || !csrfHeader || !(await auth.validateCSRFToken(sessionToken, csrfCookie, String(csrfHeader)))) {
      return res.status(403).json({ message: "CSRF validation failed" });
    }
  }
  next();
}
app.use(csrfMiddleware); // Apply CSRF middleware globally or per-route

// Login endpoint
app.post("/login", async (req, res) => {
  const { identifier, password } = req.body;
  const ipAddress = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  const result = await auth.loginUser({ input: { identifier, password }, ipAddress: String(ipAddress) });

  if (result.error) {
    return res.status(result.status).json({ message: result.message });
  }

  // Suppose result.data.rawToken is the session token.
  const rawToken = result.data?.rawToken as string;

  // Here we use createSessionCookie from the library
  let cookieStr = createSessionCookie(rawToken, 30 * 24 * 60 * 60); // 30 days session cookie

  // Create CSRF cookie alongside session cookie
  const csrfCookieStr = await auth.createCSRFCookie(rawToken);

  cookieStr = [cookieStr, csrfCookieStr].join('; '); // Combine session and CSRF cookies
  // Return a Set-Cookie header. In Express, you can do res.setHeader or res.set.
  res.setHeader("Set-Cookie", cookieStr);

  res.status(result.status).json({
    message: result.message,
    userId: result.data?.userId,
  });
});

// Protected route example
app.get("/profile", async (req, res) => {
  // Retrieve the raw token from the Cookie header using your helper
  const rawToken = getSessionTokenFromHeader(req.headers.cookie ?? null);
  if (!rawToken) {
    return res.status(401).json({ message: "No session token provided" });
  }

  const sessionCheck = await auth.validateSession(rawToken);
  if (sessionCheck.error) {
    return res.status(sessionCheck.status).json({ message: sessionCheck.message });
  }

  res.status(200).json({
    message: "Session is valid",
    session: sessionCheck.data?.session,
  });
});

// Logout endpoint
app.post("/logout", async (req, res) => {
  const rawToken = getSessionTokenFromHeader(req.headers.cookie ?? null);
  if (!rawToken) {
    return res.status(401).json({ message: "No session token found" });
  }

  // Revoke the session in DB
  const result = await auth.logoutUser(rawToken);
  if (result.error) {
    return res.status(result.status).json({ message: result.message });
  }

  // Clear the session cookie
  let clearStr = clearSessionCookie();

  const clearCsrfStr = await auth.createCSRFCookie("", 0); // Clear CSRF cookie too by setting max-age=0

  clearStr = [clearStr, clearCsrfStr].join('; ');
  res.setHeader("Set-Cookie", clearStr);

  res.status(result.status).json({ message: "Logged out" });
});

app.listen(3000, () => {
  console.log("Server listening on http://localhost:3000");
});
```

## 6. Available Methods

When you call `initSpectraAuth(prisma)`, you get an object with these methods:

1. **Registration**  
   - `registerUser({ username, email, password })`
2. **Login / Logout**  
   - `loginUser({ input: {identifier, password}, ipAddress?, deviceInfo? })`  
   - `logoutUser(rawToken)`
3. **Session Management**  
   - `createSession({ userId, deviceInfo })`
   - `validateSession(rawToken)`
   - `revokeSession(rawToken)`
4. **Email Verification**  
   - `createVerificationToken({ userId, type, expiresIn? })`
   - `useVerificationToken({ token, type })`
   - `verifyEmail(rawToken)`
5. **Password Reset**  
   - `initiatePasswordReset(email)`
   - `completePasswordReset({ token, newPassword })`
6. **CSRF Protection**
    - `createCSRFCookie(sessionToken: string)`
    - `getCSRFTokenFromCookies(cookieHeader: string | undefined)`
    - `validateCSRFToken(sessionToken: string, csrfCookieVal: string, csrfSubmittedVal: string)`

Each returns a **`SpectraAuthResult`**:

```ts
interface SpectraAuthResult {
  error: boolean;
  status: number;
  message: string;
  data?: Record<string, unknown>;
}
```

## 7. Security Considerations

**CSRF Protection is now enabled by default.**  It is **strongly recommended** to implement CSRF protection in your application's frontend for all state-changing requests (POST, PUT, DELETE).

**How to Implement CSRF Protection in Frontend (Example with Fetch API):**

1. **Read CSRF Token from Cookie:** After successful login, the server sets both a session cookie and a `spectra.csrfToken` cookie. In your frontend JavaScript, read the `spectra.csrfToken` cookie value.
2. **Include CSRF Token in Request Header:** For every `POST`, `PUT`, or `DELETE` request that modifies data or state on the server, include the CSRF token in a custom header (e.g., `X-CSRF-Token`).

```javascript
async function submitForm(data) {
  const csrfToken = getCookie('spectra.csrfToken'); // You'll need a getCookie helper

  const response = await fetch('/your-api-endpoint', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken, // Include CSRF token in header
    },
    body: JSON.stringify(data),
  });
};
```

## 8. Testing

...

## 9. License

[MIT License](./LICENSE) © 2025 [Simon Fontaine](https://github.com/Simon-Fontaine)
